package capturator;

import java.util.Date;

public class Packet {

    private String protocol;
    private String ip_src, ip_dst, direction = "Unknown";    
    private int sport, dport, lengthBytes, ttl;
    private int icmp_identifier, icmp_message; 
    private Date timestamp;  
    private String virtual_timestamp = null;
    
    //Flags TCP
    private Boolean SYN, ACK, PSH, FIN, RST, SYN_ACK;
        
    private int wrong, urgptr, ip_id;    
		
	/** CONSTRUTOR */
	public Packet(){
		SYN = false;
		ACK = false;
		PSH = false;
		FIN = false;
		RST = false;
		SYN_ACK = false;
		sport = 0;
		dport = 0;
		wrong = 0;
		urgptr = 0;
		ip_id = 0;
		ttl = 0;
		icmp_identifier = 0;
	}	
	
	public void setVirtualTimestamp(String arg0){
		virtual_timestamp = arg0;
	}
	
	public String getVirtualTimestamp(){
		return(virtual_timestamp);
	}
	
	public void setTTL(int newttl){
		ttl = newttl;
	}
	
	public int getTTL(){
		return(ttl);
	}
	
	public void setIcmp_Message(int Message){
		icmp_message = Message;
	}
	
	public int getIcmp_Message(){
		return icmp_message;
	}
	
	public void setIcmp_ID(int new_id){
		icmp_identifier = new_id;
	}
	
	public int getIcmp_ID(){
		return icmp_identifier;
	}
	
	public void setDirection(String newDirection){
		direction = newDirection;
	}
	
	public String getDirection(){
		return(direction);
	}
	
	public void setProtocol(String newProtocol){ 	//Protocol
		protocol = newProtocol;
	}
	public String getProtocol(){
		return(protocol);
	}	

	public void setIPsrc(String newIPsrc){ 	//Ip Source
		ip_src = newIPsrc;
	}
	public String getIPsrc(){
		return(ip_src);
	}

	public void setIPdst(String newIPdst){ 	//Ip Destination
		ip_dst = newIPdst;
	}
	public String getIPdst(){
		return(ip_dst);
	}

	public void setSport(int newSport){ 	//Ip Destination
		sport = newSport;
	}
	public int getSport(){
		return(sport);
	}

	public void setDport(int newDport){  	//Dport
		dport = newDport;
	}
	public int getDport(){
		return(dport);
	}

	public void setLength(int newLength){ 	//Length bytes
		lengthBytes = newLength;
	}
	public int getLength(){
		return(lengthBytes);
	}

	public void setTimestamp(Date date){ 	//Timestamp
		timestamp = date;
	}
	public Date getTimestamp(){
		return(timestamp);
	}

	public void setSYN(boolean newFlags){ 	//Flags
		SYN = newFlags;
	}
	public boolean getSYN(){
		return(SYN);
	}
	
	public void setACK(boolean newFlags){ 	//Flags
		ACK = newFlags;
	}
	public boolean getACK(){
		return(ACK);
	}
	
	public void setSYNACK(boolean newFlags){ 	//Flags
		SYN_ACK = newFlags;
	}
	public boolean getSYNACK(){
		return(SYN_ACK);
	}	

	public void setPSH(boolean newFlags){ 	//Flags
		PSH = newFlags;
	}
	public boolean getPSH(){
		return(PSH);
	}
	
	public void setRST(boolean newFlags){ 	//Flags
		RST = newFlags;
	}
	public boolean getRST(){
		return(RST);
	}		
	
	public void setFIN(boolean newFlags){ 	//Flags
		FIN = newFlags;
	}
	public boolean getFIN(){
		return(FIN);
	}		

	public void setWrong(int newWrong){ 	//Wrong Fragment
		wrong = newWrong;
	}
	public int getWrong(){
		return(wrong);
	}

	public void setUrgptr(int newUrgptr){ 	//Urgent Pointer
		urgptr = newUrgptr;
	}
	public int getUrgptr(){
		return(urgptr);
	}

	public void setIpID(int newIpID){  	//IP_ID
		ip_id = newIpID;
	}
	public int getIpID(){
		return(ip_id);
	}		
}
