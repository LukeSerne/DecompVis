from PySide6.QtCore import QLineF, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QPainter,
    QPen,
    QPolygonF,
    QFontMetricsF,
    QFont,
    QPainterPath,
    QTransform,
)
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QStyleOptionGraphicsItem,
    QHBoxLayout,
    QPushButton,
    QSlider,
    QWidget,
)

import networkx
import math
import typing

from util import Operation, layout_algorithm


class Node(QGraphicsObject):

    """A QGraphicsItem representing node in a graph"""

    COLORS: dict[str, QColor] = {
        "brown": QColor("#9E5700"),
        "green": QColor("#5AD469"),
        "red": QColor("#E31E1B"),
        "blue": QColor("#2B42E3"),
        "yellow": QColor("#D2E31B"),
        "gray": QColor("#777777"),
    }

    COLOR_NAMES: list[str] = [
        "brown", "green", "red", "blue", "yellow", "gray"
    ]

    _name: str
    _edges: list["Edge"]
    _color_name: str
    _color: QColor
    _bg_brush: QBrush
    _border_pen: QPen
    _is_selected: bool
    _rect: QRectF

    def __init__(self, item, parent=None):
        """Node constructor

        Args:
            item: Item the node represents
        """
        super().__init__(parent)

        self._name = item.get_node_name()
        self._color_name = item.get_color_name()

        self._edges = []
        self._color = self.COLORS[self._color_name]
        self._is_selected = False
        self._bg_brush = QBrush(self._color)
        self._border_pen = QPen(
            self._color.darker(), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin
        )
        self._text_pen = QPen(QColor(
            "white" if self._color_name in {"brown", "gray"} else "black"
        ))

        # Calculate bounding rect by adding a 10 pixel margin around the name
        name_rect = QFontMetricsF(QFont()).boundingRect(self._name)
        self._rect = QRectF(0, 0, name_rect.width() + 10, name_rect.height() + 10)

        self.setFlags(
            QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemSendsGeometryChanges
        )
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)

        tooltip_text = item.get_tooltip_text()
        if tooltip_text is not None:
            self.setToolTip(tooltip_text)

    def add_edge(self, edge: "Edge"):
        """Add an edge to this node"""
        self._edges.append(edge)

    def mousePressEvent(self, ev):
        super().mousePressEvent(ev)

        # Change the colour when the node is right-clicked, highlight the node
        # when middle-clicked.
        if ev.button() == Qt.RightButton:
            color_idx = self.COLOR_NAMES.index(self._color_name)
            self._color_name = self.COLOR_NAMES[(color_idx + 1) % len(self.COLOR_NAMES)]
            self._color = self.COLORS[self._color_name]
            self._bg_brush = QBrush(self._color)
            border_color = self._color.lighter() if self._is_selected else self._color.darker()
            self._border_pen = QPen(
                border_color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin
            )
            self._text_pen = QPen(QColor(
                "white" if self._color_name in {"brown", "gray"} else "black"
            ))

        elif ev.button() == Qt.MiddleButton:
            self._is_selected = not self._is_selected
            border_color = self._color.lighter() if self._is_selected else self._color.darker()
            self._border_pen = QPen(
                border_color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin
            )

        else:
            return

        self.update()

    def boundingRect(self) -> QRectF:
        """Override from QGraphicsItem

        Returns:
            QRect: Return node bounding rect
        """
        return self._rect

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(self.boundingRect(), 5, 5)
        return path

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget = None):
        """Override from QGraphicsItem

        Draw node

        Args:
            painter (QPainter)
            option (QStyleOptionGraphicsItem)
        """
        bound_rect = self.boundingRect()

        painter.setRenderHints(QPainter.Antialiasing)
        painter.setPen(self._border_pen)
        painter.setBrush(self._bg_brush)
        painter.drawRoundedRect(bound_rect, 5, 5)
        painter.setPen(self._text_pen)
        painter.drawText(bound_rect, Qt.AlignCenter, self._name)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):
        """Adjusts all edges when the item is moved"""
        if change == QGraphicsItem.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()

        return super().itemChange(change, value)


class Edge(QGraphicsItem):
    def __init__(self, source: Node, dest: Node, dest_index: int, dest_num_inputs: int, parent: QGraphicsItem = None):
        super().__init__(parent)
        self._source = source
        self._dest = dest
        self._dest_index = dest_index
        self._dest_num_inputs = dest_num_inputs

        self._tickness = 2
        self._color = "#2BB53C"
        self._arrow_size = 15

        self._source.add_edge(self)
        self._dest.add_edge(self)

        self._line = QLineF()

        self.setZValue(-1)
        self.adjust()

    def boundingRect(self) -> QRectF:
        """
        Returns a rect with corners at the centers of the source and
        destination node.
        """
        return (
            QRectF(self._line.p1(), self._line.p2())
            .normalized()
            .adjusted(
                -self._tickness - self._arrow_size,
                -self._tickness - self._arrow_size,
                self._tickness + self._arrow_size,
                self._tickness + self._arrow_size,
            )
        )

    def adjust(self):
        """
        Update edge position from source and destination node.
        This method is called from Node::itemChange
        """
        self.prepareGeometryChange()

        self._source_pos = self._source.pos() + self._source.boundingRect().center()
        target_pos = self.get_arrow_target()

        self._line = QLineF(self._source_pos, target_pos)

        angle = math.atan2(self._line.dy(), -self._line.dx())

        arrow_p1 = QPointF(
            math.sin(angle + math.pi / 3) * self._arrow_size,
            math.cos(angle + math.pi / 3) * self._arrow_size,
        )
        arrow_p2 = QPointF(
            math.sin(angle + math.pi * 2 / 3) * self._arrow_size,
            math.cos(angle + math.pi * 2 / 3) * self._arrow_size,
        )

        self._arrow_head_polygon = QPolygonF([QPointF(0, 0), arrow_p1, arrow_p2])
        self._arrow_head_polygon.translate(target_pos)

    def get_arrow_target(self) -> QPointF:
        """
        Calculate the end position of the arrow taking into account the size
        and shape of the destination node and the input id that this node represents
        """
        return self.get_edge_point(self._dest.pos(), self._dest.shape(), self._source_pos, self._dest_index, self._dest_num_inputs)

    def get_edge_point(
        self, shape_offset: QPointF, shape: QPainterPath, out_point: QPointF, offset: int, slots: int
    ) -> QPointF:

        # Translate the shape into the destination point coordinate system
        shape.translate(shape_offset)

        if shape.contains(out_point):
            return out_point

        # Move point along the line until it intersects the shape. We assume
        # there is only 1 intersection and use binary search.
        shape_box = shape.boundingRect()

        left_offset = shape_box.width() * (offset + 1) / (slots + 1)
        in_point = shape_box.topLeft() + QPointF(left_offset, 0)

        close_enough = (
            lambda a, b: abs(a.x() - b.x()) < 0.1 and abs(a.y() - b.y()) < 0.1
        )

        while not close_enough(out_point, in_point):
            mid = (out_point + in_point) / 2

            if shape.contains(mid):
                in_point = mid
            else:
                out_point = mid

        return out_point

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        """Override from QGraphicsItem

        Draw Edge. This method is called from Edge::adjust
        """
        painter.setRenderHints(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(self._color), self._tickness, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.setBrush(QBrush(self._color))
        painter.drawLine(self._line)
        painter.drawPolygon(self._arrow_head_polygon)


class GraphView(QGraphicsView):
    def __init__(self, graph: typing.Optional[networkx.DiGraph], parent=None):
        """GraphView constructor

        This widget can display a directed graph.
        """
        super().__init__()

        self._main_window = parent
        self._graph = graph
        self._scene = QGraphicsScene()
        self.setScene(self._scene)
        self.setBackgroundBrush(QColor("white"))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

        # Used to add space between nodes
        self._graph_scale = 10

        # Map node name to Node object
        self._nodes_map: dict[str, Node] = {}

        if self._graph is not None:
            self._load_graph()
            self.set_pos()

    def set_graph(self, graph: typing.Optional[networkx.DiGraph]):
        """Set the networkx graph"""
        self._graph = graph

        if graph is None:
            self.scene().clear()
            self._nodes_map.clear()
        else:
            self._load_graph()
            self.set_pos()

    def set_pos(self):
        """Set the position of nodes"""
        # Compute node position from layout function
        positions = layout_algorithm(self._graph)
        num_items = len(positions)

        # Change position of all nodes
        for node, pos in positions.items():
            x, y = pos
            item, _ = self._nodes_map[node]
            item.setPos(x, y)

    def _load_graph(self):
        """Load graph into QGraphicsScene using Node class and Edge class"""

        # TODO: Don't remove elements (nodes / edges) that are already in the
        # scene, to make the specific changes between graphs more clear.
        self.scene().clear()
        self._nodes_map.clear()

        # Add nodes
        for node, node_item in self._graph.nodes(data="node_item"):
            item = Node(node_item)
            self.scene().addItem(item)
            self._nodes_map[node] = (item, node_item)

        # Add edges
        for a, b in self._graph.edges:
            source, source_item = self._nodes_map[a]
            dest, dest_item = self._nodes_map[b]

            # When the edge points into an Operation, the arrow head of the edge
            # should be offset to indicate the input order.
            if isinstance(dest_item, Operation):
                offset = dest_item._in.index(source_item)
                slots = len(dest_item._in)
            else:
                offset = 0
                slots = 1

            self.scene().addItem(Edge(source, dest, offset, slots))

    def wheelEvent(self, event):
        """
        Called whenever the mouse wheel is moved while the cursor is over the
        graph view. This zooms the view in or out, depending on the direction of
        the mouse wheel movement.
        """
        if event.angleDelta().y() > 0:
            self._main_window._handle_zoom_in(cursor_is_center=True)
        else:
            self._main_window._handle_zoom_out(cursor_is_center=True)

    def set_zoom(self, zoom_scale: float, *, cursor_is_center: bool = False):
        """
        Set the zoom to a specific level
        """

        transform = QTransform()
        transform.scale(zoom_scale, zoom_scale)

        if cursor_is_center:
            self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

        self.setTransform(transform)

        if cursor_is_center:
            # (reset back to original transformation anchor)
            self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)

class ZoomSliderWidget(QWidget):

    def __init__(self, num_zoom_levels: int, initial_idx: int, parent: "MainWindow"):
        """
        Creates and initializes the widget
        """
        super().__init__()

        self.parent = parent
        self.num_zoom_levels = num_zoom_levels

        self.slider = QSlider(Qt.Horizontal)
        self.minus_button = QPushButton('-')
        self.plus_button = QPushButton('+')

        self.slider.setMinimum(0)
        self.slider.setMaximum(num_zoom_levels - 1)
        self.slider.setTickInterval(2)
        self.slider.setTickPosition(QSlider.TicksAbove)
        self.slider.setPageStep(1)
        self.slider.setTracking(True)
        self.slider.setSliderPosition(initial_idx)
        self.slider.valueChanged.connect(self._handle_slider_moved)

        self.minus_button.setFlat(True)
        self.plus_button.setFlat(True)
        self.minus_button.clicked.connect(parent._handle_zoom_out)
        self.plus_button.clicked.connect(parent._handle_zoom_in)

        layout = QHBoxLayout(self)
        layout.addWidget(self.minus_button)
        layout.addWidget(self.slider)
        layout.addWidget(self.plus_button)

    def _handle_slider_moved(self):
        """
        Handle the slider being moved - pass the new zoom index to the parent
        """
        self.parent._handle_update_zoom(self.slider.value())

    def set_zoom_level(self, new_zoom_idx: int):
        """
        Sets the slider position to the given index and updates the buttons
        accordingly.
        """
        self.slider.setSliderPosition(new_zoom_idx)
        self.minus_button.setEnabled(new_zoom_idx > 0)
        self.plus_button.setEnabled(new_zoom_idx < self.num_zoom_levels - 1)
