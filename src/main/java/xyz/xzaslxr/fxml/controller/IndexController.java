package xyz.xzaslxr.fxml.controller;

import com.sun.source.tree.Tree;
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
import java.util.stream.Collectors;

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

    private boolean judgeParentNode(String queryString) {
        Boolean result = false;
        boolean isStartWith = queryString.startsWith("["); // true
        boolean isEndWith = queryString.endsWith("]"); // true
        result = isStartWith && isEndWith;
        return result;
    }

    public Map<String, LinkedList<String>> getTreeItem(Packet packetData) throws Exception {
        // 看完源代码，我直接放弃找Packet类，一个个分析，感觉内部只有直接输出的功能，烦
        // Version 1 先讲
        String packetString = packetData.toString();

        // Arrays.stream(packetString.split("\n"))会将字符串按行分割，并将每行的字符串转换为一个Stream对象。
        // map(String::trim)会对每行字符串调用String.trim()方法，去除前后空格。
        // 最后，collect(Collectors.toList())会将Stream对象转换为一个List对象，即一个字符串列表。
        List<String> allData = Arrays.stream(packetString.split("\n")).map(String::trim).collect(Collectors.toList());

        // 初始化输出结果和中间变量
        Map<String, LinkedList<String>> parsedData = new LinkedHashMap<String, LinkedList<String>>();
        String currentParentNode = new String();

        // Foreach 处理数据
        for (String data : allData) {
            // judgeParentNode
            if (judgeParentNode(data)) {
                currentParentNode = data;
                parsedData.put(data, new LinkedList<String>());
            } else {
                // data is childNode
                parsedData.get(currentParentNode).add(data);
            }
        }
        return parsedData;
    }


    public LinkedList<TreeItem<String>> getTree(Map<String, LinkedList<String>> parsedData) {
        LinkedList<TreeItem<String>> treeList = new LinkedList<TreeItem<String>>();
        for (Map.Entry<String, LinkedList<String>> entry : parsedData.entrySet()) {
            String parentString = entry.getKey();
            TreeItem<String> parentNode = new TreeItem<>(parentString);
            // 将子节点添加到父节点中
            for (String str : entry.getValue()) {
                TreeItem<String> item = new TreeItem<>(str);
                parentNode.getChildren().add(item);
            }
            treeList.add(parentNode);
        }
        return treeList;
    }


    public void expandPacket(Packet packet) throws Exception {
        Map<String, LinkedList<String>> parsedData = getTreeItem(packet);
        LinkedList<TreeItem<String>> treeList = getTree(parsedData);
        treeView.setRoot(new TreeItem<String>(""));
        for (TreeItem<String> parentNode : treeList) {
            parentNode.setExpanded(true);
            treeView.getRoot().getChildren().add(parentNode);
        }
        treeView.setShowRoot(false);
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


    public void setStyle(TableColumn tablecolumn, String style) {
        tablecolumn.setStyle(style);
    }

    public void setUpTableView() throws Exception {
        id.setCellValueFactory(new PropertyValueFactory<>("id"));
        time.setCellValueFactory(new PropertyValueFactory<>("time"));
        src.setCellValueFactory(new PropertyValueFactory<>("src"));
        dst.setCellValueFactory(new PropertyValueFactory<>("dst"));
        protocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        length.setCellValueFactory(new PropertyValueFactory<>("length"));

        // 设置居中
        for(Object column : tableView.getColumns()) {
            setStyle((TableColumn) column, "-fx-alignment: CENTER;");
        }

        // Setup the view of treeView
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
                 // System.out.println(newSelection);
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
