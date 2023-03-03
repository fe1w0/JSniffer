package xyz.xzaslxr.fxml.controller;


import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.chart.*;
import javafx.scene.control.Label;
import javafx.scene.input.MouseEvent;
import javafx.scene.paint.Color;
import xyz.xzaslxr.utils.PacketModel;

import java.sql.Timestamp;
import java.util.LinkedHashMap;

/**
 * this controller for the pcap statistics view.
 * Reference: http://gitbook.net/javafx/javafx-statistics.html
 */
public class PcapStatisticsController {

    @FXML private BarChart pcapBarChart;

    @FXML private PieChart pcapPieChart;

    @FXML
    private CategoryAxis xAxis;
    @FXML
    private NumberAxis yAxis;

    @FXML
    private Label pieUnderLabel;

    private long lastTimeStamp;

    private int xAxisNumber = 6;

    private LinkedHashMap<String, Integer> axisData = new LinkedHashMap<String, Integer>();

    private LinkedHashMap<String, Integer> pieData = new LinkedHashMap<String, Integer>();

    private ObservableList<String> timeName = FXCollections.observableArrayList();

    private float packetNumber;

    /**
     * Initializes the controller class. This method is automatically called
     * after the fxml file has been loaded.
     */
    @FXML
    private void initialize() {
        // 分析数据，将数据包中的总时间按n划分，即xAxis中表示n个时间
        // yAxis表示当前时间段中收集的流量包数量
    }


    /**
     * 初始化axisData和pieData，并将分析结果保存其中。
     */
    public void getData(ObservableList<PacketModel> globalPackets) throws Exception {
        axisData = new LinkedHashMap<>();
        packetNumber = globalPackets.size();
        // 计算流量包的总时间长度
        long firstTimeStamp = getTimeStampFromPacketModel(globalPackets.get(0));
        lastTimeStamp = getTimeStampFromPacketModel(globalPackets.get(globalPackets.size() - 1));
        long timeInterval = (lastTimeStamp - firstTimeStamp) / xAxisNumber;
        for (PacketModel packetModel : globalPackets) {
            String protocolName = packetModel.getProtocol();
            long tmpTimeStamp = getTimeStampFromPacketModel(packetModel);
            int timeIndex = (int) ((tmpTimeStamp - firstTimeStamp) / timeInterval);
            long currentAxisStandardTime = firstTimeStamp + timeIndex * timeInterval;
            String timeToString = new Timestamp(currentAxisStandardTime).toString();
            if (axisData.get(timeToString) == null) {
                axisData.put(timeToString, 0);
            } else {
                int data = axisData.get(timeToString);
                axisData.put(timeToString, ++data);
            }

            if (pieData.get(protocolName) == null) {
                pieData.put(protocolName, 0);
            } else {
                int data = pieData.get(protocolName);
                pieData.put(protocolName, ++data);
            }

        }

        // 设置 UI
        setAxis();
        setPie();
    }


    /**
     * 根据pieData，渲染 xAxis 和 yAxis
     */
    public void setPie() {
        for (String key : pieData.keySet()) {
            pcapPieChart.getData().add(new PieChart.Data(key, (pieData.get(key) / packetNumber) * 100) );
        }

        pieUnderLabel.setStyle("-fx-font: 18 arial;");

        for (final PieChart.Data data : pcapPieChart.getData()) {
            data.getNode().addEventHandler(MouseEvent.MOUSE_CLICKED,
                    event -> {
                        pieUnderLabel.setText(data.getName() + ": " + data.getPieValue() + "%");
                    });
        }
        pcapPieChart.setLegendVisible(true);
    }


    /**
     * 根据axisData，渲染 xAxis 和 yAxis
     */
    public void setAxis() {
        String[] timeXAxisValue = axisData.keySet().toArray(new String[0]);
        timeName.addAll(timeXAxisValue);
        xAxis.setCategories(timeName);

        yAxis.setTickUnit(1);

        XYChart.Series<String, Integer> series = new XYChart.Series<>();
        for (String key : axisData.keySet()) {
            series.getData().add(new XYChart.Data<>(key, axisData.get(key)));
        }

        pcapBarChart.getData().add(series);
    }

    public static long getTimeStampFromPacketModel(PacketModel packetModel) throws Exception{
        Timestamp timestamp = Timestamp.valueOf(packetModel.getTime());
        return timestamp.getTime();
    }

}
