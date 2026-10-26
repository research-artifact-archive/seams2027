import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** Ordered, reversible stdout capture with independent raw and encoded caps. */
public final class BoundedDiagnosticPrintStream extends PrintStream {
  public static final String DIAGNOSTIC="lookup, class net.sf.javabdd.JTLVJavaFactory$BddCache";
  private final Encoder encoder;
  public BoundedDiagnosticPrintStream(OutputStream target,Path receipt,long rawCap,long encodedCap)throws Exception{this(new Encoder(target,receipt,rawCap,encodedCap));}
  private BoundedDiagnosticPrintStream(Encoder encoder){super(encoder,true,StandardCharsets.UTF_8);this.encoder=encoder;}
  @Override public synchronized void println(String value){if(DIAGNOSTIC.equals(value))encoder.repeat();else super.println(value);}
  public synchronized void finish()throws IOException{encoder.finish();}
  @Override public void close(){try{finish();}catch(IOException e){throw new UncheckedIOException(e);}}
  private static final class Encoder extends OutputStream {
    final OutputStream target;final Path receipt;final long rawCap,encodedCap;
    final byte[] line=(DIAGNOSTIC+System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
    final MessageDigest rawDigest,encodedDigest;
    long rawBytes,encodedBytes,repeatedLines,run,records;boolean finished,capReached;String error;
    Encoder(OutputStream target,Path receipt,long rawCap,long encodedCap)throws Exception{
      if(rawCap<=0||encodedCap<=0)throw new IllegalArgumentException("Positive capture limits required");
      this.target=target;this.receipt=receipt;this.rawCap=rawCap;this.encodedCap=encodedCap;
      rawDigest=MessageDigest.getInstance("SHA-256");encodedDigest=MessageDigest.getInstance("SHA-256");
      record("{\"kind\":\"dictionary\",\"id\":\"cache_lookup\",\"data\":\""+Base64.getEncoder().encodeToString(line)+"\"}");
    }
    private void fail(String reason,boolean cap){error=reason;capReached|=cap;throw new IllegalStateException(reason);}
    private void active(){if(finished)fail("CAPTURE_ALREADY_FINISHED",false);if(error!=null)throw new IllegalStateException(error);}
    private void admitRaw(int n){active();if(n>rawCap-rawBytes)fail("RAW_STDOUT_CAP",true);}
    private void record(String text){
      byte[] b=(text+"\n").getBytes(StandardCharsets.US_ASCII);
      if(b.length>encodedCap-encodedBytes)fail("ENCODED_STDOUT_CAP",true);
      try{target.write(b);}catch(IOException e){error="TARGET_WRITE_ERROR";throw new UncheckedIOException(e);}
      encodedDigest.update(b);encodedBytes+=b.length;records++;
    }
    private void flushRun(){if(run!=0){record("{\"kind\":\"repeat\",\"id\":\"cache_lookup\",\"count\":"+run+"}");run=0;}}
    synchronized void repeat(){admitRaw(line.length);rawDigest.update(line);rawBytes+=line.length;run++;repeatedLines++;if(run==1000000)flushRun();}
    @Override public synchronized void write(byte[] data,int off,int len){
      Objects.checkFromIndexSize(off,len,data.length);admitRaw(len);if(len==0)return;flushRun();
      for(int at=off;at<off+len;){int end=Math.min(off+len,at+65536);byte[] b=Arrays.copyOfRange(data,at,end);
        record("{\"kind\":\"bytes\",\"data\":\""+Base64.getEncoder().encodeToString(b)+"\"}");rawDigest.update(b);rawBytes+=b.length;at=end;}
    }
    @Override public synchronized void write(int value){write(new byte[]{(byte)value},0,1);}
    @Override public synchronized void flush()throws IOException{try{target.flush();}catch(IOException e){error="TARGET_FLUSH_ERROR";throw e;}}
    synchronized void finish()throws IOException{
      if(finished)return;
      try{flushRun();record("{\"kind\":\"end\",\"raw_bytes\":"+rawBytes+",\"repeated_lines\":"+repeatedLines+"}");}catch(RuntimeException e){if(error==null)error="FINISH_RECORD_ERROR";}
      try{target.flush();if(target instanceof PrintStream&&((PrintStream)target).checkError())error="TARGET_PRINTSTREAM_ERROR";}catch(IOException e){error="TARGET_FLUSH_ERROR";}
      finished=true;
      String info="{\"schema\":\"bounded-exact-println-dictionary-rle-v1\",\"capture_complete\":"+(error==null&&!capReached)
        +",\"raw_bytes\":"+rawBytes+",\"raw_sha256\":\""+HexFormat.of().formatHex(rawDigest.digest())+"\",\"encoded_bytes\":"+encodedBytes
        +",\"encoded_sha256\":\""+HexFormat.of().formatHex(encodedDigest.digest())+"\",\"repeated_lines\":"+repeatedLines+",\"unflushed_repeated_lines\":"+run
        +",\"records\":"+records+",\"raw_cap_bytes\":"+rawCap+",\"encoded_cap_bytes\":"+encodedCap+",\"cap_reached\":"+capReached
        +",\"diagnostic_line_base64\":\""+Base64.getEncoder().encodeToString(line)+"\",\"capture_error\":"+(error==null?"null":"\""+error+"\"")+"}";
      Files.writeString(receipt,info+"\n",StandardCharsets.US_ASCII,StandardOpenOption.CREATE_NEW);
    }
  }
}
