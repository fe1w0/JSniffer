package xyz.xzaslxr.utils;

import javafx.beans.property.SimpleStringProperty;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.sql.Timestamp;

public class PacketModel {
    /*
        <TableColumn prefWidth="80.0" text="id" />
        <TableColumn prefWidth="144.0" text="time" />
        <TableColumn prefWidth="144.0" text="src" />
        <TableColumn prefWidth="144.0" text="dst" />
        <TableColumn prefWidth="144.0" text="protocol" />
        <TableColumn prefWidth="144.0" text="length" />
     */

    private final SimpleStringProperty id;
    private final SimpleStringProperty time;
    private final SimpleStringProperty src;
    private final SimpleStringProperty dst;
    private final SimpleStringProperty protocol;
    private final SimpleStringProperty length;

    // 便于 解析
    private final Packet itemPacket;

    public PacketModel(Timestamp time, Short id , Packet packet) {
        if ( packet.get(IpV4Packet.class) != null) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            this.id = new SimpleStringProperty(String.valueOf(id));
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcAddr().getHostAddress());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstAddr().getHostAddress());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocol().toString());
            this.length = new SimpleStringProperty(String.valueOf(ipPacket.length()));
            // } else if (packet instanceof IpV6Packet) {
        } else {
            IpV6Packet ipPacket =  packet.get(IpV6Packet.class);
            this.id = new SimpleStringProperty(String.valueOf(id));
            this.time = new SimpleStringProperty(time.toString());
            this.src = new SimpleStringProperty(ipPacket.getHeader().getSrcAddr().getHostAddress());
            this.dst = new SimpleStringProperty(ipPacket.getHeader().getDstAddr().getHostAddress());
            this.protocol = new SimpleStringProperty(ipPacket.getHeader().getProtocol().toString());
            this.length = new SimpleStringProperty(String.valueOf(ipPacket.length()));
        }
        this.itemPacket = packet;
    }

    public String getId() {
        return this.id.get();
    }

    public void setId(String id) {
        this.id.set(id);
    }

    public SimpleStringProperty idProperty() {
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

    public String getLength() {
            return this.length.get();
        }

    public void setLength(String length) {
        this.length.set(length);
    }

    public SimpleStringProperty lengthProperty() {
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
}
