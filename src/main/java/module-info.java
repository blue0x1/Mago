module org.mago {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.controlsfx.controls;
    requires org.kordamp.bootstrapfx.core;

    opens org.mago to javafx.fxml;
    exports org.mago;
}
