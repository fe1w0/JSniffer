package xyz.xzaslxr.fxml.controller;

import javafx.beans.Observable;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;

public class IndexController implements Initializable {

    // 列出所有网卡
    @FXML private ComboBox interfacesComboBox;
    // 开始嗅探
    @FXML private Button startSniffer;
    // 终止嗅探
    @FXML private Button endSniffer;

    private List<PcapNetworkInterface> localInterfaces;

    private int selectedInterfaceIndex;

    @Override
    public void initialize(URL location, ResourceBundle resources) {

        try {
            localInterfaces =  Pcaps.findAllDevs();
            // 将 localInterfaces 转为 JavaFX 可识别的对象。
            ObservableList<PcapNetworkInterface> interfaceLists = FXCollections.observableList(localInterfaces);
            // 设置 interfacesComboBox 的数据来源
            interfacesComboBox.setItems(interfaceLists);
            // 设置 interfacesComboBox 默认选择 第1项
            interfacesComboBox.getSelectionModel().select(0);

            // 设置 startSniffer 的操作
            startSniffer.setOnAction(event -> {
                selectedInterfaceIndex = interfacesComboBox.getSelectionModel().getSelectedIndex();

            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
