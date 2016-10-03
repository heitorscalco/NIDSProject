package preprocessor;

import preprocessor.Config;
import java.io.PrintStream;
import java.net.Socket;

public class Communicator {	
	private static Socket new_client;	
	public static void sendMessage(String parameters) {
	    try {
			new_client = new Socket(Config.host_address, Config.dest_port);     	     
			PrintStream input = new PrintStream(new_client.getOutputStream());	      
			input.println(parameters);
			input.close();	 
			new_client.close();
	    }
	    catch(Exception e) {
	      System.out.println("Error: " + e.getMessage());
	    }
	  }	
}

	