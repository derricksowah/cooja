package org.contikios.cooja.plugins;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.contikios.cooja.ClassDescription;
import org.contikios.cooja.Cooja;
import org.contikios.cooja.Plugin;
import org.contikios.cooja.PluginType;
import org.contikios.cooja.Simulation;

import org.jdom2.Element;

@ClassDescription("Headless IEEE 802.15.4 PCAP Logger")
@PluginType(PluginType.PType.SIM_PLUGIN)
public class HeadlessPcapLogger implements Plugin {

  private final Simulation simulation;

  private File pcapFile;
  private DataOutputStream out;

  private Object lastConnection;

  public HeadlessPcapLogger(
      final Simulation simulation,
      final Cooja gui) {

    this.simulation = simulation;
  }


  private void openPcap() throws IOException {

    if(out != null) {
      return;
    }

    if(pcapFile == null) {
      pcapFile =
          new File("headless-radiolog.pcap");
    }

    File parent =
        pcapFile.getAbsoluteFile().getParentFile();

    if(parent != null) {
      parent.mkdirs();
    }

    out =
        new DataOutputStream(
            new FileOutputStream(pcapFile));

    /*
     * Standard PCAP global header.
     *
     * LINKTYPE 195 =
     * IEEE 802.15.4 without FCS assumptions
     * matching the existing Cooja PcapExporter.
     */
    out.writeInt(0xa1b2c3d4);
    out.writeShort(0x0002);
    out.writeShort(0x0004);
    out.writeInt(0);
    out.writeInt(0);
    out.writeInt(4096);
    out.writeInt(195);

    out.flush();

    System.out.println(
        "HEADLESS_PCAP_OPEN,file="
        + pcapFile.getAbsolutePath());
  }


  private void writePacket(
      byte[] data,
      long timestamp) {

    if(data == null) {
      return;
    }

    try {

      if(out == null) {
        openPcap();
      }

      out.writeInt(
          (int)(timestamp / 1000000));

      out.writeInt(
          (int)(timestamp % 1000000));

      out.writeInt(data.length);
      out.writeInt(data.length);

      out.write(data);
      out.flush();

    } catch(IOException e) {

      System.err.println(
          "HEADLESS_PCAP_ERROR,"
          + e.getMessage());
    }
  }


  @Override
  public javax.swing.JInternalFrame getCooja() {
    return null;
  }

  public org.contikios.cooja.Mote getMote() {
    return null;
  }

  @Override
  public void startPlugin() {

    try {
      openPcap();
    } catch(IOException e) {
      throw new RuntimeException(
          "Unable to open PCAP file",
          e);
    }

    var radioMedium =
        simulation.getRadioMedium();

    radioMedium
        .getRadioTransmissionTriggers()
        .addTrigger(
            this,
            (obs, obj) -> {

              var conn =
                  radioMedium
                      .getLastConnection();

              if(conn == null) {
                return;
              }

              /*
               * Radio transmission triggers may fire
               * more than once for the same connection.
               */
              if(conn == lastConnection) {
                return;
              }

              lastConnection = conn;

              var packet =
                  conn.getSource()
                      .getLastPacketTransmitted();

              if(packet == null) {
                return;
              }

              byte[] data =
                  packet.getPacketData();

              writePacket(
                  data,
                  conn.getStartTime());
            });

    System.out.println(
        "HEADLESS_PCAP_STARTED");
  }


  @Override
  public void closePlugin() {

    simulation
        .getRadioMedium()
        .getRadioTransmissionTriggers()
        .deleteTriggers(this);

    if(out != null) {

      try {
        out.flush();
        out.close();
      } catch(IOException ignored) {
      }

      out = null;
    }

    System.out.println(
        "HEADLESS_PCAP_CLOSED");
  }


  @Override
  public Collection<Element> getConfigXML() {

    ArrayList<Element> config =
        new ArrayList<>();

    if(pcapFile != null) {

      Element e =
          new Element("pcap_file");

      e.setText(
          pcapFile
              .getPath()
              .replace("\\", "/"));

      config.add(e);
    }

    return config;
  }


  @Override
  public boolean setConfigXML(
      Collection<Element> configXML,
      boolean visAvailable) {

    for(Element element : configXML) {

      if(
          "pcap_file".equals(
              element.getName())) {

        pcapFile =
            new File(
                element.getText());
      }
    }

    return true;
  }
}
