package xyz.xzaslxr.fxml.controller;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Callback;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import xyz.xzaslxr.utils.PacketModel;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static xyz.xzaslxr.utils.Sniffer.*;

public class Controller implements Initializable {


    @FXML private VBox root;

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

    @FXML private TextField textField = new TextField();

    @FXML private Button handleField = new Button();

    // 添加 menu 功能
    @FXML private MenuItem mainPage;

    @FXML private MenuItem dataAnalysisPage;

    @FXML private MenuItem savePcapFile;

    @FXML private MenuItem openPcapFile;

    @FXML private MenuItem aboutPage;

    // 输入的 TextField
    private String textFieldInput = "";

    // false 表示当前表格数据为gotPackets,
    // true 表示当前表格为 filter 后的数据.
    public boolean isFilter = false;

    // snifferState 用于记录和表示App的状态，
    // true 表示运行
    // false 表示已经终止
    public boolean snifferState = false;

    public String selectedRowString = "";

    private List<PcapNetworkInterface> localInterfaces;

    private int selectedInterfaceIndex;

    private CopyOnWriteArrayList<PacketModel> gotPackets = new CopyOnWriteArrayList<PacketModel>();

    private ObservableList<PacketModel> globalPackets;
    private PcapHandle runningHandle;

    private PacketModel oldSelectedPacket = null;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        try {
            setUpInterfacesComboBox();
            setUpTableView();
            setUpTextField();
            setUpMenu();
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
        // 思路： 直接将所有的输出按行分割
        // 再判断 ParentNode 和 ChildNode
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


    // 展开Packet，并修改treeView
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

    public void listenGotPackets() throws Exception {
        // 添加 List 监听器
        try {
            if ( !isFilter) {
                refreshTable(gotPackets);
            } else {
                CopyOnWriteArrayList<PacketModel> packets = getFilterPacketList(runningHandle, textFieldInput, gotPackets);
                refreshTable(packets);
            }
        } catch (Exception e) {
            refreshTable(gotPackets);
            System.out.println("[!] Failed to refresh table: textFieldInput");
            e.printStackTrace();
        }
    }

    // 最头疼的地方
    // 想换成callback
    public void refreshTable(CopyOnWriteArrayList<PacketModel> packets) throws Exception {
        // 根据传入的 packets 刷新
        ObservableList<PacketModel> packetsTable = FXCollections.observableArrayList(packets);
        tableView.setRowFactory(new Callback<TableView<PacketModel>, TableRow<PacketModel>>() {
            @Override
            public TableRow<PacketModel> call(TableView<PacketModel> param) {
                final TableRow<PacketModel> row = new TableRow<PacketModel>() {
                    @Override
                    protected void updateItem(PacketModel packetModel, boolean empty) {
                        super.updateItem(packetModel, empty);
                        if (packetModel != null && selectedRowString != "") {
                            if (highlightTableItems(packetModel)){
                                setStyle("-fx-background-color: #6795e3;");
                            } else {
                                setStyle("-fx-background-color: #ffffff;");
                            }
                        }
                    }
                };
                return row;
            }
        });
        tableView.getItems().setAll(packetsTable);
    }


    public void setStyle(TableColumn tablecolumn, String style) {
        tablecolumn.setStyle(style);
    }

    public void setCellValueFactory(TableColumn tablecolumn, PropertyValueFactory propertyValueFactory) {
        tablecolumn.setCellValueFactory(propertyValueFactory);
    }

    public boolean highlightTableItems(PacketModel packetModel) {
        // 检查当前的row的packetModel的StreamString，是否与当前
        return (selectedRowString.equals(packetModel.getStreamString()));
    }

    public void setUpTableView() throws Exception {
        // 设置 setCellValueFactory
        for(Object column : tableView.getColumns()) {
            setCellValueFactory((TableColumn) column, new PropertyValueFactory<>( ((TableColumn) column).getId()) );
        }

        // 设置居中
        for(Object column : tableView.getColumns()) {
            ((TableColumn) column).setSortable(true);
            setStyle((TableColumn) column, "-fx-alignment: CENTER;");
        }

        // 设置 compare
        id.setComparator(new PacketModel.IdCompare());
        length.setComparator(new PacketModel.LengthCompare());
        id.setSortType(TableColumn.SortType.ASCENDING);
        length.setSortType(TableColumn.SortType.ASCENDING);


        tableView.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
             if (oldSelectedPacket != null && newSelection != null && !oldSelectedPacket.compare((PacketModel) newSelection)) {
                 oldSelectedPacket = (PacketModel) newSelection;
                 try {
                     expandPacket( ((PacketModel) newSelection).getItemPacket());
                     // 设置 selectRowString
                     selectedRowString = ((PacketModel) newSelection).getStreamString();
                 } catch (Exception e) {
                     throw new RuntimeException(e);
                 }
            } else if (oldSelectedPacket == null && newSelection != null) {
                 oldSelectedPacket = (PacketModel) newSelection;
                 try {
                     expandPacket( ((PacketModel) newSelection).getItemPacket());
                     selectedRowString = ((PacketModel) newSelection).getStreamString();
                 } catch (Exception e) {
                     throw new RuntimeException(e);
                 }
             }
        });
    }

    /*
        在下拉框中添加所有网卡信息，
        并设置 startSniffer 和 endSniffer 的按钮操作
     */
    public void setUpInterfacesComboBox() throws Exception {
        localInterfaces =  Pcaps.findAllDevs();
        // 将 localInterfaces 转为 JavaFX 可识别的对象。
        ObservableList<PcapNetworkInterface> interfaceLists = FXCollections.observableList(localInterfaces);
        // 设置 interfacesComboBox 的数据来源
        interfacesComboBox.setItems(interfaceLists);
        // 设置 interfacesComboBox 默认选择 第1项
        interfacesComboBox.getSelectionModel().select(0);

        startSniffer.setOnAction(event -> {
            try {
                // 必须得开一个 javafx Task，避免线程卡死，UI也卡死
                Task<Void> task = new Task<Void>() {
                    @Override
                    protected Void call() throws Exception {
                        // 清空 gotPackets
                        gotPackets.clear();
                        // 重置 snifferState
                        snifferState = true;
                        // 重置 isFilter
                        isFilter = false;
                        // 重置 streamMap
                        selectedRowString = "";
                        // 重置 TableView
                        globalPackets = FXCollections.observableArrayList(gotPackets);
                        tableView.getItems().setAll(globalPackets);
                        // 添加 packetsTable 的监听器
                        globalPackets.addListener(new ListChangeListener<PacketModel>() {
                            @Override
                            public void onChanged(Change<? extends PacketModel> c) {
                                try {
                                    listenGotPackets();
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }
                        });

                        // 根据下拉框中的下标，创建pcapHandler
                        selectedInterfaceIndex = interfacesComboBox.getSelectionModel().getSelectedIndex();
                        runningHandle = getPcapHandler(localInterfaces.get(selectedInterfaceIndex));
                        try {
                            // 开始启动监听模块
                            runSniffer(runningHandle, gotPackets, globalPackets);
                        } catch (Exception e) {
                            System.out.println("[!] Error: startSniffer.runSniffer");
                            throw new RuntimeException(e);
                        }
                        return null;
                    }
                };
                new Thread(task).start();
            } catch (Exception e) {
                System.out.println("[!] Error: startSniffer.setOnAction");
            }
        });

        // 设置 endSniffer
        endSniffer.setOnAction(event -> {
            try {
                endSnifferMethod();
            } catch (Exception e) {
                System.out.println("[!] Error: endSniffer");
                throw new RuntimeException(e);
            }
        });
    }


    public void endSnifferMethod() throws Exception {
        snifferState = false;
        zeroCounter();
        if (runningHandle != null && runningHandle.isOpen()) {
            runningHandle.breakLoop();
            runningHandle.close();
        }
    }

    public void setUpTextField() {
        textField.setEditable(true);
        textField.setPromptText("请输入查询语句:");
        textField.setAlignment(Pos.CENTER_LEFT);

        // 设置 listener
        textField.textProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                // 获得输入文本
                isFilter = false;
                textFieldInput = newValue;
            }
        });

        handleField.setOnAction(event -> {
            try {
                isFilter = true;

                // 添加暂停时，对 TableView的刷新
                if (!snifferState) {
                    // 手动监听
                    listenGotPackets();
                }
            } catch (Exception e) {
                System.out.println("[!] Error: handleField");
                e.printStackTrace();
            }
        });
    }

    public void setUpMenu() {
        // 设置 savePcapFile
        savePcapFile.setOnAction(event -> {
            try {
                // EndSniffer
                endSnifferMethod();
                // https://stackoverflow.com/questions/30464238/javafx-getscene-returns-null
                Scene scene = root.getScene();
                invokeSaveFileChooser(scene);
            } catch (Exception e) {
                System.out.println("[+] Start to save the pack to path of file");
                throw new RuntimeException(e);
            }
        });

        // 设置 openPcapFile
        openPcapFile.setOnAction(event -> {
            try {
                // EndSniffer
                endSnifferMethod();
                Scene scene = root.getScene();
                invokeOpenFileChooser(scene);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }


    public void invokeOpenFileChooser(Scene scene) throws Exception {

        FileChooser openFileChooser = new FileChooser();
        openFileChooser.setTitle("打开文件");
        openFileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        // 给文件对话框添加文件类型过滤器
        openFileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("pcap文件(*.pcap)", "*.pcap"),
                new FileChooser.ExtensionFilter("所有文件(*.*)", "*.*")
        );
        File openFile = openFileChooser.showOpenDialog(scene.getWindow());
        if (openFile != null) {
            try {
                if (globalPackets == null) {
                    globalPackets = FXCollections.observableArrayList(gotPackets);
                }
                gotPackets = new CopyOnWriteArrayList<PacketModel>();
                globalPackets.remove(0, globalPackets.size() - 1);
                globalPackets.addListener(new ListChangeListener<PacketModel>() {
                    @Override
                    public void onChanged(Change<? extends PacketModel> c) {
                        try {
                            listenGotPackets();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
                runningHandle = Pcaps.openOffline(openFile.getAbsolutePath());
                openPacketFile(runningHandle, gotPackets, globalPackets);
            } catch (Exception e) {
                warningAlert("打开文件错误");
                e.printStackTrace();
            }
        }


    }

    public void invokeSaveFileChooser(Scene scene) throws Exception {
        // invoke file chooser to save the packet
        FileChooser saveFileChooser = new FileChooser();
        saveFileChooser.setTitle("保存文件");
        // 设置默认地址，为脚本运行的地址
        saveFileChooser.setInitialDirectory(new File(System.getProperty("user.dir")));
        // 创建文件类型过滤器 *.pcap
        FileChooser.ExtensionFilter filter = new FileChooser.ExtensionFilter("pcap文件(*.pcap)", "*.pcap");
        // 给文件对话框添加文件类型过滤器
        saveFileChooser.getExtensionFilters().add(filter);
        // 显示保存的对话框
        File file = saveFileChooser.showSaveDialog(scene.getWindow());

        if (file == null || runningHandle == null || gotPackets == null) {
            // 处理无效选择，可能弹窗吧
            warningAlert("产生异常，请查看是否选择文件和是否开启嗅探器，以及是否嗅探到数据包。");
        } else {
            savePackets(runningHandle, file, gotPackets);
        }
    }

    public void warningAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setHeaderText("错误");
        alert.setContentText(message);
        alert.show();
    }
}


