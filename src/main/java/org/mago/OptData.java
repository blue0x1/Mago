package org.mago;

public class OptData {
    private final String ipAddress;
    private final int port;
    private final String shellType;
    private final String osType;

    public OptData(String ipAddress, int port, String shellType, String osType) {
        this.ipAddress = ipAddress;
        this.port = port;
        this.shellType = shellType;
        this.osType = osType;
    }

    public String getIpAddress() { return ipAddress; }
    public int getPort() { return port; }
    public String getShellType() { return shellType; }
    public String getOsType() { return osType; }
}
