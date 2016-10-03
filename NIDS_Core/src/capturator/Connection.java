package capturator;

import java.util.Date;
import java.util.LinkedHashMap;

public class Connection {
	
	private String protocol; 					//Protocol
    private int sport=-1, dport=-1;
    private int cid;
    private int sizeFromSourceToDest, sizeFromDestToSource; 
    private Date primeiroTS, ultimoTS;			// timestamp do primeiro pacote recebido    
    private Date virtualTs; 					// timestamp virtual usado para checar o timeout da conexão
    private int urgptr; 						// numero de urgent pointers
    private int timeout; 						// tempo de timeout da conexão
    private boolean timeouted; 					// indica que a conexão já sofreu timeout
    private String flag_conexao = "Unknown"; 				// flag da Conexao
    private String connection_status = "Unknown"; 			// Estado da conexao
    private int last_packet_analysed = 0;		// Último pacote analisado para determinar o estado da conexão
    private String service = "other";
    private String unique_id = null, virtual_unique_id = null, virtual_reverse_unique_id = null;
    private boolean dont_analyse;
    private int sttl = 0, dttl = 0;
    private int SourceToDestPkts = 0, DestToSourcePkts = 0;    
    

    //Flags TCP
    private int flags_tcp_count_FIN;
    private int flags_tcp_count_SYN;
    private int flags_tcp_count_RST;        
    private int flags_tcp_count_SYN_ACK;

    private String ip_source=null, ip_dest=null; 			//Source and Destination IP Address    
    private float duration; 				//Duration
    private int land; 						//Land
    private int wrong_fragments; 			//Wrong Fragments
    private int numberofpackets;
    //private List<Pacote> pacotes = new ArrayList<Pacote>();	
	private LinkedHashMap<String, Connection> buffer = new LinkedHashMap<String, Connection>();
	
	
	/**
	 * Test features
	 */
	
	public String parm_time = null;
	public String parm_connections = null;
	
	/** CONSTRUTOR */
	public Connection(){
		sizeFromSourceToDest = 0;
		sizeFromDestToSource = 0;
		urgptr = 0;
		timeout = 0;
		flags_tcp_count_FIN = 0;
		flags_tcp_count_RST = 0;
		flags_tcp_count_SYN = 0;
		flags_tcp_count_SYN_ACK = 0;
		duration = 0;
		land = 0;
		wrong_fragments = 0;
		dont_analyse = false;
	}
	
	public void setVirtualUniqueID(String unique){
		virtual_unique_id = unique;
	}
	
	public String getVirtualUniqueID(){
		return(virtual_unique_id);
	}
	
	public void setReverseVirtualUniqueID(String unique){
		virtual_reverse_unique_id = unique;
	}
	
	public String getReverseVirtualUniqueID(){
		return(virtual_reverse_unique_id);
	}
	
	public void addSourceToDestPkts(){
		SourceToDestPkts++;
	}
	
	public int getSourceToDestPkts(){
		return(SourceToDestPkts);
	}
	
	public void addDestToSourcePkts(){
		DestToSourcePkts++;
	}
	
	public int getDestToSourcePkts(){
		return(DestToSourcePkts);
	}
	
	
	public void setDTTL(int ttl){
		dttl = ttl;
	}
	
	public int getDTTL(){
		return(dttl);
	}
	
	public void setSTTL(int ttl){
		sttl = ttl;
	}
	
	public int getSTTL(){
		return(sttl);
	}
	
	public void setDont_Analyse(boolean action){
		dont_analyse = action;
	}
	
	public boolean getDont_Analyse(){
		return(dont_analyse);
	}
	
	public void setUnique_id(String unique){
		unique_id = unique;
	}
	
	public String getUnique_id(){
		return unique_id;
	}
	
	public void setService(String newService){
		service = newService;
	}
	
	public String getService(){
		return(service);
	}
	
	public void setLastPacketAnalysed(int Npacket){
		last_packet_analysed = Npacket;	
	}
	
	public int getLastPacketAnalysed(){
		return(last_packet_analysed);
	}
	
	public void setConnectionStatus(String status){
		connection_status = status;
	}
	
	public String getConnectionStatus(){		
		return(connection_status);
	}
	
	public LinkedHashMap<String, Connection> getbuffer(){
		return(buffer);
	}	
    
    public void addPacketCounter(){
    	numberofpackets++;
    }
    
    public int getNumOfPackets(){
    	return(numberofpackets);
    }
    
    public void setSport(int newsport){
    	sport = newsport;
    }
    public int getSport(){
    	return(sport);
    }
    
    public void setDport(int newdport){
    	dport = newdport;
    }
    public int getDport(){
    	return(dport);
    }
    
    public void setCID(int newcid){
    	cid = newcid;
    }
    public int getCID(){
    	return(cid);
    }
    
    public void setSizeFromSourceToDest(int newsize){
    	sizeFromSourceToDest = newsize;
    }
    
    public void addSizeFromSourceToDest(int size_to_add){
    	sizeFromSourceToDest += size_to_add;
    }     
  
    public void setSizeFromDestToSource(int newsize){
    	sizeFromDestToSource = newsize;
    }
    
    public void addSizeFromDestToSource(int size_to_add){
    	sizeFromDestToSource += size_to_add;
    }
    
    public int getSizeFromSourceToDest(){
    	return(sizeFromSourceToDest);
    }
    
    public int getSizeFromDestToSource(){
    	return(sizeFromDestToSource);
    }
    
    public void setPrimeiroTS (Date date){
    	primeiroTS = date;
    }    
    public Date getPrimeiroTS(){
    	return(primeiroTS);
    }
    
    public void setUltimoTS (Date newts){
    	ultimoTS = newts;
    }    
    public Date getUltimoTS(){
    	return(ultimoTS);
    }
    
    public void setVirtualTS (Date date){
    	virtualTs = date;
    }    
    public Date getVirtualTS(){
    	return(virtualTs);
    }
   
    public void setUrgptr(int newurg){
    	urgptr = newurg;
    }
    
    public void addUrgptr(int newurg){
    	urgptr += newurg;
    }
    
    public int getUrgptr(){
    	return(urgptr);
    }
    
    public void setTimeout(int newtime){
    	timeout = newtime;
    }
    public int getTimeout(){
    	return(timeout);
    }
    
    public void setTimeouted(boolean option){
    	timeouted = option;
    }
    public boolean getTimeouted(){
    	return(timeouted);
    }
    
    public void setFlagConexao(String newflag){
    	flag_conexao = newflag;
    }
    public String getFlagConexao(){
    	return(flag_conexao);
    }
    
    public void setFIN(int flag){
    	flags_tcp_count_FIN = flag;
    }
    public int getFIN(){
    	return(flags_tcp_count_FIN);
    }
    
    public void setRST(int flag){
    	flags_tcp_count_RST = flag;
    }
    public int getRST(){
    	return(flags_tcp_count_RST);
    }
    
    public void setSYN(int flag){
    	flags_tcp_count_SYN = flag;
    }
    public int getSYN(){
    	return(flags_tcp_count_SYN);
    }
    
    public void setSYNACK(int flag){
    	flags_tcp_count_SYN_ACK = flag;
    }
    public int getSYN_ACK(){
    	return(flags_tcp_count_SYN_ACK);
    }
    
    public void setIPsource(String ip){
    	ip_source = ip;
    }
    public String getIPsource(){
    	return(ip_source);
    }
    
    public void setIPdestination(String ip){
    	ip_dest = ip;
    }
    public String getIPdestination(){
    	return(ip_dest);
    }
    
    public void setDuration(float time){
    	duration = time;
    }
    public float getDuration(){
    	return(duration);
    }
   
    public void setLand(int newland){
    	land = newland;
    }
    public int getLand(){
    	return(land);
    }
    
    public void setWrong(int newwrong){
    	wrong_fragments = newwrong;
    }
    
    public void addWrong(int newwrong){
    	wrong_fragments += newwrong;
    }
    
    public int getWrong(){
    	return(wrong_fragments);
    }
    
    public void setProtocol(String newproto){
    	protocol = newproto;
    }
    public String getProtocol(){
    	return(protocol);
    }           
}
