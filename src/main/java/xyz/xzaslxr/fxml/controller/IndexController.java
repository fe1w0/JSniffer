package xyz.xzaslxr.fxml.controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import xyz.xzaslxr.utils.PacketModel;

import java.net.URL;
import java.util.*;

import static xyz.xzaslxr.utils.Sniffer.*;

public class IndexController implements Initializable {

    // ComboBox 列出所有网卡
    @FXML private ComboBox interfacesComboBox;
    // Button 开始嗅探
    @FXML private Button startSniffer;
    // Button 终止嗅探
    @FXML private Button endSniffer;
    // TableView tableView
    @FXML private TableView tableView;

    @FXML private TableColumn id = new TableColumn();;

    @FXML private TableColumn time = new TableColumn();;

    @FXML private TableColumn src = new TableColumn();;

    @FXML private TableColumn dst = new TableColumn();;

    @FXML private TableColumn protocol = new TableColumn();

    @FXML private TableColumn length = new TableColumn();

    @FXML private TreeView treeView = new TreeView();

    private List<PcapNetworkInterface> localInterfaces;

    private int selectedInterfaceIndex;

    private List<PacketModel> gotPackets = new LinkedList<PacketModel>();

    private PcapHandle runningHandle;

    private PacketModel oldSelectedPacket = null;

    @Override
    public void initialize(URL location, ResourceBundle resources) {

        try {
            setUpInterfacesComboBox();
            setUpTableView();
            refreshTable();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void expandPacket(Packet packet) throws Exception {

        TreeItem<String> root = new TreeItem<>("Root");
        TreeItem<String> item1 = new TreeItem<>("Item 1");
        TreeItem<String> item2 = new TreeItem<>("Item 2");
        TreeItem<String> item3 = new TreeItem<>("Item 3");

        root.getChildren().add(item1);
        item1.getChildren().add(item2);
        item2.getChildren().add(item3);


        System.out.println(packet.toString());
    }

    public void refreshTable() throws Exception {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            public void run() {
                Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<PacketModel> packetsTable = FXCollections.observableArrayList(gotPackets);
                        tableView.getItems().setAll(packetsTable);
                    }

                });
            }
        }, 1000, 1000);
    }

    public void setUpTableView() throws Exception {
        id.setCellValueFactory(new PropertyValueFactory<>("id"));
        time.setCellValueFactory(new PropertyValueFactory<>("time"));
        src.setCellValueFactory(new PropertyValueFactory<>("src"));
        dst.setCellValueFactory(new PropertyValueFactory<>("dst"));
        protocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        length.setCellValueFactory(new PropertyValueFactory<>("length"));

        ObservableList<PacketModel> packetsTable = FXCollections.observableArrayList(gotPackets);
        tableView.getItems().setAll(packetsTable);

        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
             if (oldSelectedPacket != null && newSelection != null && !oldSelectedPacket.compare((PacketModel) newSelection)) {
                 oldSelectedPacket = (PacketModel) newSelection;
                 try {
                     expandPacket( ((PacketModel) newSelection).getItemPacket());
                 } catch (Exception e) {
                     throw new RuntimeException(e);
                 }
                 System.out.println(newSelection);
            } else if (oldSelectedPacket == null && newSelection != null) {
                 oldSelectedPacket = (PacketModel) newSelection;
                 try {
                     expandPacket( ((PacketModel) newSelection).getItemPacket());
                 } catch (Exception e) {
                     throw new RuntimeException(e);
                 }
             }
        });


    }

    public void setUpInterfacesComboBox() throws Exception {
        localInterfaces =  Pcaps.findAllDevs();
        // 将 localInterfaces 转为 JavaFX 可识别的对象。
        ObservableList<PcapNetworkInterface> interfaceLists = FXCollections.observableList(localInterfaces);
        // 设置 interfacesComboBox 的数据来源
        interfacesComboBox.setItems(interfaceLists);
        // 设置 interfacesComboBox 默认选择 第1项
        interfacesComboBox.getSelectionModel().select(0);

        startSniffer.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                Task<Void> task = new Task<Void>() {
                    @Override
                    protected Void call() throws Exception {
                        // 清空 gotPackets
                        gotPackets.clear();
                        // 清空 TableView
                        ObservableList<PacketModel> packetsTable = FXCollections.observableArrayList(gotPackets);
                        tableView.getItems().setAll(packetsTable);

                        selectedInterfaceIndex = interfacesComboBox.getSelectionModel().getSelectedIndex();
                        runningHandle = getPcapHandler(localInterfaces.get(selectedInterfaceIndex));
                        try {
                            runSniffer(runningHandle, gotPackets);
                        } catch (Exception e) {
                            System.out.println("[!] Error: startSniffer");
                            throw new RuntimeException(e);
                        }
                        return null;
                    }
                };
                new Thread(task).start();
            }
        });


        // 设置 endSniffer
        endSniffer.setOnAction(event -> {
            try {
                runningHandle.breakLoop();
                zeroCounter();
            } catch (Exception e) {
                System.out.println("[!] Error: endSniffer");
                throw new RuntimeException(e);
            }
        });
    }
}
