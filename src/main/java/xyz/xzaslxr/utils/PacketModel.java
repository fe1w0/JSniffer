package xyz.xzaslxr.utils;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IcmpV4Type;

import java.sql.Timestamp;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.TreeSet;

public class PacketModel {

    private final SimpleIntegerProperty id;
    private final SimpleStringProperty time;
    private final SimpleStringProperty src;
    private final SimpleStringProperty dst;
    private final SimpleStringProperty protocol;
    private final SimpleIntegerProperty length;

    private String streamString;

    // 便于 解析
    private final Packet itemPacket;

    public PacketModel(Timestamp time, Short id , Packet packet) {

        if ( packet.get(IpV4Packet.class) != null) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            this.id = new SimpleIntegerProperty(id);
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcAddr().getHostAddress());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstAddr().getHostAddress());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocol().toString());
            this.length = new SimpleIntegerProperty(ipPacket.length());
        } else if (packet.get(IpV6Packet.class) != null) {
            IpV6Packet ipPacket = packet.get(IpV6Packet.class);
            this.id = new SimpleIntegerProperty(id);
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcAddr().getHostAddress());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstAddr().getHostAddress());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocol().toString());
            this.length = new SimpleIntegerProperty(ipPacket.length());
        } else if (packet.get(ArpPacket.class) != null ){
            ArpPacket ipPacket = packet.get(ArpPacket.class);
            this.id = new SimpleIntegerProperty(id);
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcHardwareAddr().toString());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstHardwareAddr().toString());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocolType().toString());
            this.length = new SimpleIntegerProperty(ipPacket.length());
        } else {
            System.out.println("[!] Invalid protocol");
            System.out.println(packet);
            IpV6Packet ipPacket =  packet.get(IpV6Packet.class);
            this.id = new SimpleIntegerProperty(id);
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcAddr().getHostAddress());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstAddr().getHostAddress());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocol().toString());
            this.length = new SimpleIntegerProperty(ipPacket.length());
        }
        this.itemPacket = packet;
        getStreamS();
    }

    public String getStreamString() {
        return streamString;
    }

    public void getStreamS() {
        String srcAddr = "";
        String dstAddr = "";
        if (itemPacket.get(IpV4Packet.class) != null) {
            srcAddr = itemPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
            dstAddr = itemPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString();
        } else if (itemPacket.get(IpV6Packet.class) != null) {
            srcAddr = itemPacket.get(IpV6Packet.class).getHeader().getSrcAddr().toString();
            dstAddr = itemPacket.get(IpV6Packet.class).getHeader().getDstAddr().toString();
        }
            if (itemPacket.get(TcpPacket.class) != null) {
            streamString = getStreamString(
                    srcAddr,
                    itemPacket.get(TcpPacket.class).getHeader().getSrcPort().toString(),
                    dstAddr,
                    itemPacket.get(TcpPacket.class).getHeader().getSrcPort().toString(),
                    true
            );
        } else if (itemPacket.get(UdpPacket.class) != null) {
            streamString = getStreamString(
                    srcAddr,
                    itemPacket.get(UdpPacket.class).getHeader().getSrcPort().toString(),
                    dstAddr,
                    itemPacket.get(UdpPacket.class).getHeader().getSrcPort().toString(),
                    false
            );
        } else if (itemPacket.get(IcmpV4CommonPacket.class) != null) {
            streamString = getStreamString(
                    itemPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString(),
                    itemPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString(),
                    itemPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString(),
                    itemPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString(),
                    false
            );
        }
    }

    public String getStreamString(String src, String srcPort, String dst, String dstPort, boolean isTcp) {
        // 确保 小字符串 在前
        if ((src + srcPort).compareTo(dst + dstPort) < 0 ) {
            if (isTcp) {
                return src + srcPort + dst + dstPort + "TCP";
            } else {
                return src + srcPort + dst + dstPort + "UDP";
            }
        } else {
            if (isTcp) {
                return dst + dstPort + src + srcPort + "TCP";
            } else {
                return dst + dstPort + src + srcPort + "UDP";
            }
        }
    }

    public int getId() {
        return this.id.get();
    }

    public void setId(int id) {
        this.id.set(id);
    }

    public SimpleIntegerProperty idProperty() {
        return this.id;
    }

    public String getTime() {
        return this.time.get();
    }

    public void setTime(String time) {
        this.time.set(time);
    }

    public SimpleStringProperty timeProperty() {
        return time;
    }

    public String getSrc() {
        return this.src.get();
    }

    public SimpleStringProperty srcProperty() {
        return src;
    }

    public void setSrc(String src) {
            this.src.set(src);
        }

    public String getDst() {
        return this.dst.get();
    }

    public void setDst(String dst) {
            this.dst.set(dst);
    }

    public SimpleStringProperty dstProperty() {
        return dst;
    }

    public String getProtocol() {
        return this.protocol.get();
    }

    public void setProtocol(String protocol) {
        this.protocol.set(protocol);
    }

    public SimpleStringProperty protocolProperty() {
        return protocol;
    }

    public int getLength() {
            return this.length.get();
        }

    public void setLength(int length) {
        this.length.set(length);
    }

    public SimpleIntegerProperty lengthProperty() {
        return length;
    }

    public Packet getItemPacket() {
        return itemPacket;
    }
    @Override
    public String toString() {
        return itemPacket.toString();
    }

    public Boolean compare(PacketModel value) {
        if (itemPacket.equals(value.itemPacket)) {
            return true;
        } else {
            return false;
        }
    }

    public static class IdCompare implements Comparator<Integer> {
        @Override
        public int compare(Integer o1, Integer o2) {
            return o1.compareTo(o2);
        }
    }

    public static class LengthCompare implements Comparator<Integer> {
        @Override
        public int compare(Integer o1, Integer o2) {
            return o1.compareTo(o2);
        }
    }
}
