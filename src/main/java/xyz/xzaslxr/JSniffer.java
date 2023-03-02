package xyz.xzaslxr;

import javafx.application.Application;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;

import static xyz.xzaslxr.utils.Sniffer.savePackets;


public class JSniffer extends Application {

    public static void main(String[] args) {
        launch(args); // 启动JavaFX应用，之后会调用start方法
    }

    @Override
    public void start(Stage stage) throws Exception {
        stage.setTitle("Java Sniffer @ fe1w0"); // 舞台标题

        // 从FXML资源文件中加载程序的初识界面
        Parent root = FXMLLoader.load(getClass().getResource("fxml/index.fxml"));

        Scene scene = new Scene(root, 800, 600);

        // 设置舞台的场景
        stage.setScene(scene);
        // 不允许 舞台尺寸被变化
        stage.setResizable(true);
        // 展示舞台
        stage.show();
    }
}