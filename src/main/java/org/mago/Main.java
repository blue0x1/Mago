package org.mago;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.net.URL;
import java.util.Base64;
import java.util.List;

public class Main extends Application {
    @Override
    public void start(Stage primaryStage) {

        primaryStage.setTitle("Mago - Shell Generator");
        primaryStage.getIcons().add(new Image(getClass().getResource("/logo.png").toExternalForm()));

        Label aboutLink = new Label("About");
        aboutLink.setStyle("-fx-text-fill: white; -fx-font-size: 14px; -fx-font-family: 'San Francisco'; ");
        aboutLink.setOnMouseEntered(e -> aboutLink.setCursor(Cursor.HAND));
        aboutLink.setOnMouseClicked(event -> showAboutDialog());

        Label ipLabel = new Label("IP Address:");
        TextField ipField = new TextField();
        ipField.setPromptText("Enter IP address");

        Label portLabel = new Label("Port:");
        TextField portField = new TextField();
        portField.setPromptText("Enter port");

        Label shellTypeLabel = new Label("Shell Type:");
        ComboBox<String> shellTypeBox = new ComboBox<>();

        Label osTypeLabel = new Label("Operating System:");
        ComboBox<String> osTypeBox = new ComboBox<>();
        osTypeBox.getItems().addAll("Linux", "Windows", "Web");
        osTypeBox.setValue("Linux");

        Label encodingLabel = new Label("Encoding Options:");
        CheckBox base64Check = new CheckBox("Base64");
        CheckBox urlEncodeCheck = new CheckBox("URL Encode");

        Button generateButton = new Button("Generate Payload");
        Button copyButton = new Button("Copy to Clipboard");

        Label outputLabel = new Label("Generated Command:");
        TextArea outputArea = new TextArea();
        outputArea.setEditable(false);

        List<String> linuxPayloads = List.of(
                "bash", "bash_udp", "bash_base64", "sh_tcp", "sh_udp", "python", "python3", "python_websocket",
                "R", "perl", "perl_ipv6", "php", "ruby", "vlang", "groovy", "scala", "dart", "msbuild_proj",
                "bash_env", "ruby_tls", "nc", "ncat_ssl", "curl", "mkfifo", "xterm", "ksh", "dash", "screen",
                "tmux", "awk_tcp", "awk_udp", "nodejs", "nodejs_udp", "java", "go", "c", "rust", "nim", "prolog",
                "erlang", "crystal", "racket", "julia", "d", "smalltalk", "scheme", "lua", "busybox", "socat",
                "socat_ssl", "elixir", "clojure", "tcl", "haskell", "gawk", "zsh", "telnet", "openssl", "docker"
        );

        List<String> windowsPayloads = List.of(
                "powershell_basic", "powershell_encoded", "powershell_iex", "powershell_bind_tcp", "powershell_udp",
                "nc", "curl", "certutil", "wscript", "mshta", "revdll", "wmic", "invoke_wmi", "regsvr32", "bitsadmin",
                "scriptrunner", "rundll32_in_mem", "registry", "msiexec", "schtasks", "python_win", "java_win",
                "batch", "autolt", "vbs", "C#", ".Net", "C++", "php"
        );

        List<String> webPayloads = List.of(
                "php_basic", "php_reverse", "php_eval", "php_passthru", "php_shell_exec", "php_laravel",
                "php_backconnect", "php_socket_reverse", "php_websocket", "asp_basic", "asp_reverse", "jsp_basic",
                "jsp_reverse", "coldfusion_basic", "perl_cgi", "python_flask", "python_tornado", "python_django",
                "nodejs_express", "asp_net", "asp_net_core", "tomcat_jsp", "go_http", "ruby_sinatra",
                "rails_controller", "java_springboot"
        );

        osTypeBox.setOnAction(event -> {
            String selectedOS = osTypeBox.getValue();
            shellTypeBox.getItems().clear();
            switch (selectedOS) {
                case "Linux" -> shellTypeBox.getItems().addAll(linuxPayloads);
                case "Windows" -> shellTypeBox.getItems().addAll(windowsPayloads);
                case "Web" -> shellTypeBox.getItems().addAll(webPayloads);
            }
            shellTypeBox.setValue(shellTypeBox.getItems().get(0));
        });
        osTypeBox.fireEvent(new javafx.event.ActionEvent());

        generateButton.setOnAction(event -> {
            String ip = ipField.getText();
            String portText = portField.getText();
            String shellType = shellTypeBox.getValue();
            String osType = osTypeBox.getValue();

            String ipPattern = "^([a-zA-Z0-9.-]+|([0-9]{1,3}\\.){3}[0-9]{1,3}|([a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{1,4})$";

            if (!ip.matches(ipPattern)) {
                outputArea.setText("Please enter a valid IP address, IPv6 address, or hostname.");
                return;
            }

            if (portText.isEmpty() || !portText.matches("\\d+")) {
                outputArea.setText("Please enter a valid numeric port.");
                return;
            }

            int port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) {
                outputArea.setText("Port must be between 1 and 65535.");
                return;
            }

            OptData options = new OptData(ip, port, shellType, osType);
            ShellCmd shellCommand = GenUtil.generate(options);
            String command = shellCommand.getCommand();

            if (base64Check.isSelected()) command = Base64.getEncoder().encodeToString(command.getBytes());
            if (urlEncodeCheck.isSelected()) command = command.replaceAll(" ", "%20");

            outputArea.setText(command);
        });

        copyButton.setOnAction(event -> {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(outputArea.getText());
            clipboard.setContent(content);
        });

        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(8);
        grid.setHgap(10);

        HBox topRight = new HBox(aboutLink);
        topRight.setAlignment(Pos.TOP_RIGHT);
        grid.add(topRight, 2, 0);

        grid.add(ipLabel, 0, 1);
        grid.add(ipField, 1, 1);
        grid.add(portLabel, 0, 2);
        grid.add(portField, 1, 2);
        grid.add(shellTypeLabel, 0, 3);
        grid.add(shellTypeBox, 1, 3);
        grid.add(osTypeLabel, 0, 4);
        grid.add(osTypeBox, 1, 4);
        grid.add(encodingLabel, 0, 5);
        grid.add(base64Check, 1, 5);
        grid.add(urlEncodeCheck, 2, 5);
        grid.add(generateButton, 1, 6);
        grid.add(copyButton, 2, 6);
        grid.add(outputLabel, 0, 7);
        grid.add(outputArea, 0, 8, 3, 1);

        Scene scene = new Scene(grid, 550, 450);
        URL cssUrl = getClass().getClassLoader().getResource("theme.css");
        if (cssUrl != null) scene.getStylesheets().add(cssUrl.toExternalForm());

        primaryStage.setScene(scene);
        primaryStage.show();
    }
    private void showAboutDialog() {
        Stage aboutStage = new Stage();
        aboutStage.initModality(Modality.APPLICATION_MODAL);
        aboutStage.setTitle("About Mago");
        aboutStage.getIcons().add(new Image(getClass().getResource("/logo.png").toExternalForm()));
        // Logo
        ImageView logoView = new ImageView(new Image(getClass().getResource("/logo.png").toExternalForm()));
        logoView.setFitWidth(150);
        logoView.setFitHeight(230);

        // Version label
        Label versionLabel = new Label("Mago v1.0.0");
        versionLabel.setStyle("-fx-text-fill: #dcdcdc; -fx-font-size: 14px; -fx-font-style: italic;");

        // Copyright label
        Label rightsLabel = new Label("© 2024 Chokri Hammedi. All rights reserved.");
        rightsLabel.getStyleClass().add("copyright-label");

        // GitHub link
        Hyperlink githubLink = new Hyperlink("https://github.com/blue0x1");
        githubLink.getStyleClass().add("link-label");
        githubLink.setOnAction(e -> getHostServices().showDocument(githubLink.getText()));

        // Layout for the dialog content
        VBox contentBox = new VBox(10, logoView, versionLabel, rightsLabel, githubLink);
        contentBox.setPadding(new Insets(10));
        contentBox.setAlignment(Pos.CENTER);

        // Scene for the dialog
        Scene aboutScene = new Scene(contentBox, 400, 350);
        aboutScene.getStylesheets().add(getClass().getResource("/theme.css").toExternalForm());
        aboutStage.setScene(aboutScene);
        aboutStage.showAndWait();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
