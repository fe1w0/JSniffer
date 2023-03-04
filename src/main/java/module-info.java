module xyz.xzaslxr.jsniffer {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.pcap4j.core;
    requires java.sql;


    opens xyz.xzaslxr.jsniffer to javafx.fxml;

    exports xyz.xzaslxr.jsniffer;
    exports xyz.xzaslxr.jsniffer.controller;
    exports xyz.xzaslxr.jsniffer.utils;

    opens xyz.xzaslxr.jsniffer.utils to javafx.base;
    opens xyz.xzaslxr.jsniffer.controller to javafx.fxml;
}