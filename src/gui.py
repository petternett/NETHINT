import math
from collections import defaultdict
import numpy as np
import pyqtgraph as pg
from PyQt6.QtWidgets import (
        QApplication,
        QGridLayout,
        QCheckBox,
        QVBoxLayout,
        QHBoxLayout,
        QWidget,
        QGraphicsView,
        QGraphicsScene,
        QPushButton,
        QGraphicsWidget,
        QLabel,
        QSlider,
)

from PyQt6.QtCore import Qt
from pyqtgraph.Qt import QtCore, QtGui, QtWidgets
from multiprocessing import Process, Pipe, Event
import socket
from DataPoint import DataPoint
from common import isset_relative_time, check_mode

VENDOR_LOOKUP = True
try:
    from mac_vendor_lookup import MacLookup, BaseMacLookup
except ImportError:
    VENDOR_LOOKUP = False


PLOT_RTT  = 0
PLOT_LOSS = 1
PLOT_OWD  = 2
UPDATE_VALUE = 3
UPDATE_EWMA = 4

RTT_IDX   = 0
RSSI_IDX  = 1
RATE_IDX  = 2
NOISE_IDX = 3

mp_plot = None
def init_plot_obj() -> None:
    global mp_plot
    mp_plot = MPPlot()

def plot_data(data: DataPoint) -> None:
    mp_plot.plot_data(data)


class ValueWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)

        # self.setText("")

    def update(self, text=""):
        self.setText(text)


class MyPlotWidget(pg.GraphicsLayoutWidget):
    def __init__(self, parent=None, pipe=None):
        super().__init__(parent)

        BaseMacLookup.cache_path = "./mac_lookup-cache"
        self.mac = MacLookup()

        self.pipe = pipe

        self.rtt_plots:  dict[str, ScatterPlotItem] = defaultdict(pg.ScatterPlotItem)
        self.rssi_plots: dict[str, ScatterPlotItem] = defaultdict(pg.ScatterPlotItem)
        self.plot_lines: dict[str, InfiniteLine] = defaultdict(list)
        self.show_plot_lines: bool = True
        self.owd_plots:  dict[str, LinePlotItem] = defaultdict(pg.PlotCurveItem)
        self.value_widget = self.parent().findChild(ValueWidget)

        # First 3 colors are defined, others are random
        self.colors = iter([[255, 70, 70], [70, 200, 255], [70, 255, 70]])
        self.brushes: dict[str, QtGui.QBrush] = defaultdict(lambda: pg.mkBrush(next(self.colors, np.random.randint(0, 256, 3))))
        self.mac_hosts: dict[str, str] = {}


        # --- TCP RTT Scatter plot --- #
        self.rtt_plot_item = self.addPlot(row=0, col=0)
        self.rtt_plot_item.setLabel('bottom', 'Time')
        if check_mode() == "wireless":
            self.rtt_plot_item.setLabel('left', 'RTT per device')
        else:
            self.rtt_plot_item.setLabel('left', 'RTT per flow')
        self.rtt_plot_item.showGrid(x=True, y=True)

        # Axes
        y_axis = pg.AxisItem(orientation='left')
        y_axis.setGrid(128)
        if check_mode() == "wireless":
            y_axis.setLabel(text='RTT per device', units='s')  # pg dislikes scaling prefexes
        else:
            y_axis.setLabel(text='RTT per flow', units='s')

        x_axis = (pg.DateAxisItem(orientation='bottom', utcOffset=0)
                  if isset_relative_time()
                  else pg.DateAxisItem(orientation='bottom'))
        x_axis.setGrid(128)
        x_axis.setLabel(text='Time')

        self.rtt_plot_item.setAxisItems({'bottom': x_axis, 'left': y_axis})

        # RTT Plot Legend
        self.rtt_plot_item.addLegend()

        # Scrolling plot iterator
        self.n_show = 10


        # --- Radiotap RSSI Scatter plot --- #
        self.rssi_plot_item = self.addPlot(row=1, col=0)
        self.rssi_plot_item.setLabel('bottom', 'Time')
        if check_mode() == "wireless":
            self.rssi_plot_item.setLabel('left', 'Signal strength per host')
        else:
            self.rssi_plot_item.setLabel('left', 'Signal strength per flow')
        self.rssi_plot_item.showGrid(x=True, y=True)
        # self.rssi_plot_item.invertY(True)

        # Axes
        y_axis = pg.AxisItem(orientation='left')
        y_axis.setGrid(128)
        y_axis.setLabel(text='Signal strength per host', units='dBm')

        x_axis = (pg.DateAxisItem(orientation='bottom', utcOffset=0)
                  if isset_relative_time()
                  else pg.DateAxisItem(orientation='bottom'))
        x_axis.setGrid(128)
        x_axis.setLabel(text='Time')

        self.rssi_plot_item.setAxisItems({'bottom': x_axis, 'left': y_axis})

        # RSSI Plot Legend
        self.rssi_plot_item.addLegend()

        # Signal range scale changes
        self.rssi_plot_item.setXLink(self.rtt_plot_item)

        # Only show RSSI plot in wireless mode
        if check_mode() != "wireless": self.rssi_plot_item.hide()


        # --- OWD Line chart --- #
        self.owd_plot_item = self.addPlot(row=2, col=0)
        self.owd_plot_item.setLabel('bottom', 'Time')
        self.owd_plot_item.setLabel('left', 'Relative OWD')
        self.owd_plot_item.showGrid(x=True, y=True)
        self.owd_plot_x = defaultdict(list)
        self.owd_plot_y = defaultdict(list)
        self.ewma_plots = defaultdict(list)
        self.ewma_alpha = 1
        self.ewma_old = {}

        # Axes
        y_axis = pg.AxisItem(orientation='left')
        y_axis.setGrid(128)
        y_axis.setLabel(text='Relative OWD')  # No unit as smoothed value is not in ms anymore

        x_axis = (pg.DateAxisItem(orientation='bottom', utcOffset=0)
                  if isset_relative_time()
                  else pg.DateAxisItem(orientation='bottom'))
        x_axis.setGrid(128)
        x_axis.setLabel(text='Time')

        self.owd_plot_item.setAxisItems({'bottom': x_axis, 'left': y_axis})

        # RSSI Plot Legend
        self.owd_plot_item.addLegend()

        # Signal range scale changes
        self.owd_plot_item.setXLink(self.rtt_plot_item)

        # --- Update timer --- #
        self.timer = pg.QtCore.QTimer()
        self.timer.timeout.connect(self.update)
        self.timer.setInterval(1000)
        self.timer.start()


    def toggle_loss_lines(self):
        neg = not self.show_plot_lines
        for flow in self.plot_lines.values():
            for item in flow:
                item.setVisible(neg)
        self.show_plot_lines = neg

    def toggle_view_plot(self, idx: int) -> None:
        match idx:
            case 0:
                plot = self.rtt_plot_item
            case 1:
                plot = self.rssi_plot_item
            case 2:
                plot = self.owd_plot_item

        plot.setVisible(not plot.isVisible())

    def host_mac_lookup(self, addr):
        if addr not in self.mac_hosts:
            self.mac_hosts[addr] = self.mac.lookup(addr)

        return self.mac_hosts[addr]


    def update(self) -> None:
        scatter_time_buf = defaultdict(list)
        rtt_buf  = defaultdict(list)
        rssi_buf = defaultdict(list)
        datapoint_buf = {}
        loss_buf = defaultdict(list)
        owd_buf  = defaultdict(list)
        owd_time_buf = defaultdict(list)
        n_rtt = n_loss = n_owd = 0

        update_smoothness = None

        while self.pipe.poll():

            buf: DataPoint | None = self.pipe.recv()
            
            # TODO: is None unused
            if buf is None:
                return

            # Different types of buf[0]:
            # 0: RTT         - data: (rtt, rssi, rate, noise)
            # 1: Packet loss - data: (None)
            # 2: OWD         - data: (OWD)
            # 3: Value update
            plot_type = buf[0]
            buf = buf[1]

            if plot_type == UPDATE_VALUE:
                self.value_widget.update(buf)
                continue
            
            # --- Update smoothness --- #
            if plot_type == UPDATE_EWMA:
                update_smoothness = buf
                continue

            # For local and emulated, display destination IPs instead of MACs.
            flow_key = (f"{buf.mac_a}>{buf.mac_b}"
                        if check_mode() == "wireless"
                        else f"{buf.ip_src}>{buf.ip_dst}")

            # Only needs to be set once per flow key
            if flow_key not in datapoint_buf:
                datapoint_buf[flow_key] = buf

            # --- RTT and RSSI --- #
            # Update scatter plots
            if plot_type == PLOT_RTT:
                scatter_time_buf[flow_key].append(buf.time)
                rtt_buf[flow_key].append(buf.data[RTT_IDX])
                rssi_buf[flow_key].append(buf.data[RSSI_IDX])
                n_rtt += 1
                continue

            # --- Packet loss --- #
            if plot_type == PLOT_LOSS:
                loss_buf[flow_key].append(buf.time)
                n_loss += 1
                continue

            # --- OWD --- #
            if plot_type == PLOT_OWD and len(self.rtt_plots[flow_key].data) > 0:
                owd_time_buf[flow_key].append(buf.time)
                owd_buf[flow_key].append(buf.data)
                n_owd += 1


        if update_smoothness is not None:
            # new_alpha = (100-update_smoothness) * 0.01  # Linear
            new_alpha = pow(0.83*math.e, -0.06*update_smoothness)  # Exponential
            self.ewma_alpha = new_alpha
            self.ewma_update_all()

        self.update_scatter_plots(scatter_time_buf, rtt_buf, rssi_buf, datapoint_buf)
        self.update_loss(loss_buf)
        self.update_owd_plot(owd_time_buf, owd_buf, datapoint_buf)
        # print(f"Added points: {n_rtt} RTT, {n_loss} Loss, {n_owd} OWD.")

    """ Add new ScatterPlotItems to PlotItems if first in current flow. """
    def create_scatter_plot(self, buf: DataPoint, flow_key: str) -> None:
            # In wireless mode, set name to MAC vendor 
            _name = ""
            if check_mode() == 'wireless':
                vendor = self.host_mac_lookup(buf.mac_a)
                _name = f"{vendor}_{buf.mac_a[9:]}"
            else:
                _name = f"{buf.ip_src}"

            # Create brush
            brush = self.brushes[flow_key]

            # New RTT plot
            if len(self.rtt_plots[flow_key].data) == 0:
                # Create scatterplot, set brush
                new_scatter = pg.ScatterPlotItem(
                        name=_name,
                        hoverable=True,
                        tip='RTT: {y:.5g} s'.format)
                new_scatter.setBrush(brush)
                # new_scatter.sigClicked.connect(self.on_points_clicked)

                # Add new scatterplot
                self.rtt_plots[flow_key] = new_scatter
                self.rtt_plot_item.addItem(new_scatter)

            # New RSSI plot
            if len(self.rssi_plots[flow_key].data) == 0:
                # Create scatterplot
                new_scatter = pg.ScatterPlotItem(
                        name=_name,
                        hoverable=True,
                        tip='RSSI: {y:.3g}'.format)
                new_scatter.setBrush(brush)
                # new_scatter.sigClicked.connect(self.on_points_clicked)

                # Add new scatterplot
                self.rssi_plots[flow_key] = new_scatter
                self.rssi_plot_item.addItem(new_scatter)

    """ Add new Line plot to PlotItems if first in current flow. """
    def create_owd_plot(self, buf: DataPoint, flow_key: str) -> None:
            # In wireless mode, set name to MAC vendor 
            _name = ""
            if check_mode() == 'wireless':
                vendor = self.host_mac_lookup(buf.mac_a)
                _name = f"{vendor}_{buf.mac_a[9:]}"
            else:
                _name = f"{buf.ip_src}"

            # Create brush
            _pen = pg.mkPen(self.brushes[flow_key].color(), width=1)
            if len(self.owd_plots[flow_key].getData()[0]) == 0:
                # Create line chart, set pen
                new_curve = pg.PlotCurveItem(
                        pen=_pen,
                        name=_name,
                        hoverable=True,
                        tip='OWD diff: {y:.5g}'.format)

            # Add new curve
            self.owd_plots[flow_key] = new_curve
            self.owd_plot_item.addItem(new_curve)

    """ Update OWD line chart """
    def update_owd_plot(self, time_dict, owd_dict, datapoint_buf) -> None:
        for flow_key in time_dict:
            # Only plot for flows we have other data for
            if len(self.rtt_plots[flow_key].data) == 0:
                return
            if len(self.owd_plots[flow_key].getData()[0]) == 0:
                self.create_owd_plot(datapoint_buf[flow_key], flow_key)

            # Plot points (OWD delta divided by 1000 because of pg.AxisItem unit scaling)
            self.owd_plot_x[flow_key] += time_dict[flow_key]
            self.owd_plot_y[flow_key] += owd_dict[flow_key]
            self.ewma_plots[flow_key] += self.ewma_add(flow_key, owd_dict[flow_key])
            self.owd_plots[flow_key].setData(self.owd_plot_x[flow_key], self.ewma_plots[flow_key])
            # self.owd_plots[flow_key].setData(self.owd_plot_x[flow_key], self.owd_plot_y[flow_key])

    """ Update RTT and RSSI scatter plots """
    def update_scatter_plots(self, time_list, rtt_list, rssi_list, datapoint_buf) -> None:
        for flow_key in time_list:
            # RTT and RSSI plots
            if len(self.rtt_plots[flow_key].data) == 0:
                self.create_scatter_plot(datapoint_buf[flow_key], flow_key)
            self.rtt_plots[flow_key].addPoints(time_list[flow_key], rtt_list[flow_key])
            self.rssi_plots[flow_key].addPoints(time_list[flow_key], rssi_list[flow_key])


    """ Update plots with lines indicating packet loss """
    def update_loss(self, loss_buf: dict[str, [int]]) -> None:
        # Plot vertical lines
        for flow_key in loss_buf:
            # Only plot for flows we have other data for
            if len(self.rtt_plots[flow_key].data) == 0:
                return

            color = self.brushes[flow_key].color()
            color.setAlphaF(0.4)
            for loss_time in loss_buf[flow_key]:
                loss_line = pg.InfiniteLine(pos=loss_time, angle=90, pen=color)
                self.plot_lines[flow_key].append(loss_line)
                loss_line.setVisible(self.show_plot_lines)
                self.rtt_plot_item.addItem(loss_line)

    """ Return new relative OWD delay times based on current EWMA alpha """
    def ewma_add(self, flow_key: str, owd_vals) -> [float]:
        ewma_old = self.ewma_old.get(flow_key, 0)
        new_list: [float] = []

        for val in owd_vals:
            new_ewma = ewma_old * (1-self.ewma_alpha) + val * self.ewma_alpha
            new_list.append(new_ewma)
            ewma_old = new_ewma

        return new_list

    """ Update all relative OWD delay times in all flows based on new EWMA alpha """
    def ewma_update_all(self) -> None:
        for flow_key in self.owd_plot_y:
            ewma_old = 0
            new_list: [float] = []
            plot_vals = self.owd_plot_y[flow_key]

            for val in plot_vals:
                new_ewma = ewma_old * (1-self.ewma_alpha) + val * self.ewma_alpha
                new_list.append(new_ewma)
                ewma_old = new_ewma

            self.ewma_old[flow_key] = ewma_old
            self.ewma_plots[flow_key] = new_list

            self.owd_plots[flow_key].setData(self.owd_plot_x[flow_key], self.ewma_plots[flow_key])

class MPPlot:
    def __init__(self):
        # Pipe: Receiver <- Sender
        self.out_pipe, self.in_pipe = Pipe(duplex=False)

        self.stop_event = Event()
        self.mp_plot = Process(target=self.start_receiver, args=(self.out_pipe, self.stop_event,))
        self.mp_plot.start()

        # TODO stop_event.set() on program exit


    def plot_data(self, data):
        self.in_pipe.send(data)

    def start_receiver(self, out_pipe, stop_event):
        # TODO if stop_event.is_set(): main_widget.close()
        app = QApplication([])

        main_widget = QWidget()
        main_widget.setWindowTitle("NETHINT")

        # Create widgets
        self.value_widget = ValueWidget(main_widget)
        plot_widget = MyPlotWidget(parent=main_widget, pipe=out_pipe)

        loss_button = QPushButton("Toggle packet loss lines")
        loss_button.clicked.connect(plot_widget.toggle_loss_lines)

        rtt_plot_button = QPushButton("Toggle RTT plot")
        rtt_plot_button.clicked.connect(lambda: plot_widget.toggle_view_plot(0))
        rssi_plot_button = QPushButton("Toggle RSSI plot")
        rssi_plot_button.clicked.connect(lambda: plot_widget.toggle_view_plot(1))
        if check_mode() != "wireless": rssi_plot_button.setEnabled(False)
        owd_plot_button = QPushButton("Toggle OWD plot")
        owd_plot_button.clicked.connect(lambda: plot_widget.toggle_view_plot(2))

        slider_text   = QLabel("Smoothness:")
        slider_widget = QSlider(Qt.Orientation.Horizontal)
        slider_value  = QLabel("0%")

        slider_widget.setMaximum(100)
        slider_widget.setTracking(False)
        slider_widget.valueChanged.connect(lambda value: self.plot_data((UPDATE_EWMA, value)))
        slider_widget.valueChanged.connect(lambda value: slider_value.setText(f"{value}%"))

        # Create layout
        layout = QGridLayout()
        main_widget.setLayout(layout)

        toggle_plots_layout = QGridLayout()
        toggle_plots_layout.addWidget(rtt_plot_button, 0, 0)
        toggle_plots_layout.addWidget(rssi_plot_button, 0, 1)
        toggle_plots_layout.addWidget(owd_plot_button, 0, 2)

        smooth_layout = QHBoxLayout()
        smooth_layout.addWidget(slider_text)
        smooth_layout.addWidget(slider_widget)
        smooth_layout.addWidget(slider_value)

        # Add widgets
        layout.addWidget(plot_widget, 0, 0)
        layout.addWidget(loss_button, 1, 0)
        layout.addLayout(toggle_plots_layout, 2, 0)
        layout.addWidget(self.value_widget, 3, 0)
        layout.addLayout(smooth_layout, 4, 0)

        main_widget.show()
        app.exec()
