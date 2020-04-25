import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.HttpsURLConnection;

/*
 * A utility that uses virustotal to evaluate all currently running processes.
 * This program currently does not upload files.
 */
public class ProcessScanner {
	
	private int max_failures; // maximum consecutive failures
	private int csc_failures; // consecutive failures
	
	private File log_file; // output log meant for human eyes
	private File rec_file; // for the program to know which processes were already scanned
	
	private int skip_count; // how many processes were skipped
	private int scan_count; // how many processes were "scanned"
	private int susp_count; // how many processes were marked with "malicious" or "suspicious"
	
	private boolean show_skip;
	
	public ProcessScanner(int max_failures, File log_file, File rec_file) {
		this.max_failures = max_failures;
		this.log_file = log_file;
		this.rec_file = rec_file;
	}
	
	public int getSkipCount() {
		return skip_count;
	}

	public int getScanCount() {
		return scan_count;
	}

	public int getSuspiciousCount() {
		return susp_count;
	}
	
	public void setShowSkippedProcess(boolean value) {
		show_skip = value;
	}
	
	public boolean showSkippedProcesses() {
		return show_skip;
	}
	
	public List<String> getProcessList() {
		ArrayList<String> list = new ArrayList<String>();
		try {
			Process ps = Runtime.getRuntime().exec("ps -e -W");
			BufferedReader response = new BufferedReader(
					new InputStreamReader(
					ps.getInputStream()));
			String line;
			response.readLine(); // ignore the first line
			while((line=response.readLine())!=null) {
				int path_begin = line.indexOf("C:");
				if(path_begin!=-1) {
					list.add(line.substring(path_begin).trim());
				}
			}
			response.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return list;
	}
	
	public Set<String> getProcessSet() {
		return new HashSet<String>(getProcessList());
	}
	
	private String byteArrayToString(byte[] bin) {
		StringBuilder str = new StringBuilder();
		for(int i=0;i<bin.length;i++) {
			str.append(String.format("%02x",bin[i]));
		}
		return str.toString();
	}
	
	private byte[] getFileHash(String path) {
		try {
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(path));
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			byte[] buffer = new byte[1024];
			int bytes_read;
			while((bytes_read=in.read(buffer,0,buffer.length))!=-1) {
				sha256.update(buffer,0,bytes_read);
			}
			in.close();
			return sha256.digest();
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public Map<String,Integer> scanFile(String path) {
		return scanHash(byteArrayToString(getFileHash(path)));
	}
	
	public Map<String,Integer> scanHash(String hash) {

		final String user_agent = 
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
				"AppleWebKit/537.36 (KHTML, like Gecko) "+
				"Chrome/79.0.3945.130 "+
				"Safari/537.36";
		
		try {
			
			// check if the file has already been scanned on virustotal before
			
			String url = "https://www.virustotal.com/ui/files/"+hash;
			HttpsURLConnection urlc = (HttpsURLConnection)new URL(url).openConnection();
			urlc.setRequestMethod("GET");
			urlc.setRequestProperty("user-agent",user_agent);
			urlc.setRequestProperty("authority","www.virustotal.com");
			urlc.setRequestProperty("path","/ui/files/"+hash);
			urlc.setRequestProperty("scheme","https");
			urlc.setRequestProperty("accept","application/json");
			urlc.setRequestProperty("accept-encoding","gzip, deflate, br");
			urlc.setRequestProperty("accept-language","en-US,en;q=0.9,ja;q=0.8");
			urlc.setRequestProperty("cache-control","no-cache");
			urlc.setRequestProperty("pragma","no-cache");
			urlc.setRequestProperty("referer","https://www.virustotal.com/");
			urlc.setRequestProperty("sec-fetch-mode","cors");
			urlc.setRequestProperty("sec-fetch-site","same-origin");
			urlc.setRequestProperty("x-app-hostname","https://www.virustotal.com/gui/");
			urlc.setRequestProperty("x-app-version","202000218t083105");
			
			String response; {
				BufferedReader in = new BufferedReader(
						new InputStreamReader(
						new GZIPInputStream(
						urlc.getInputStream())));
				StringBuilder text = new StringBuilder();
				int c;
				while((c=in.read())!=-1) {
					text.append((char)c);
				}
				in.close();
				response = text.toString();
			}
			
			// find section of json that contains the info we want
			int info_index = response.indexOf("\"last_analysis_stats\"");
			String[] json = response.substring(
					response.indexOf("{",info_index)+1,
					response.indexOf("}",info_index)).trim().split("\n");

			HashMap<String,Integer> info = new HashMap<String,Integer>();
			
			for(int i=0;i<json.length;i++) {
				int index = json[i].lastIndexOf(":");
				String key = json[i].substring(0,index).trim();
				key = key.substring(1,key.length()-1); // strip quotes
				String val = json[i].substring(index+1).trim();
				val = val.substring(0,val.length()-1); // remove comma
				info.put(key,Integer.parseInt(val));
			}
			
			return info;
			
		} catch(Exception e) {
			e.printStackTrace();
			// either virustotal is temp blocking us
			// or has never seen the file before
		}
		
		return null;
	}
	
	public Set<String> getIgnoreSet() {
		HashSet<String> ignore = new HashSet<String>();
		try {
			BufferedReader in = new BufferedReader(
					new InputStreamReader(
					new FileInputStream(rec_file)));
			String line;
			while((line=in.readLine())!=null) {
				ignore.add(line.trim());
			}
			in.close();
		} catch(Exception e) {
			e.printStackTrace();
			System.out.println("error accessing previously scanned paths...");
		}
		return ignore;
	}
	
	public void scan() {
		
		skip_count = 0;
		scan_count = 0;
		
		PrintWriter log = getPrintWriter(log_file,"output log");
		PrintWriter rec = getPrintWriter(rec_file,"previously accessed files");
		
		Set<String> ignore = getIgnoreSet();
		
	    for(String process : getProcessSet()) {
	    	try {
	    		
	    		if(ignore.contains(process)) {
	    			if(show_skip) {
	    				System.out.println("skipping process: "+process);
	    			}
	    			skip_count++;
	    			continue;
	    		}
	    		
	    		System.out.println("scanning process: "+process);
	    		
		    	Map<String,Integer> results = scanFile(process);
		    	
		    	if(log!=null) {
		    		log.println(process);
		    	}
		    	
		    	boolean hit = false;
		    	for(String key : results.keySet()) {
		    		int val = results.get(key);
		    		if(val>0) {
		    			String line = "  "+key+": "+val;
		    			PrintStream out = System.out;
		    			if(key.equals("malicious") || key.equals("suspicious")) {
		    				out = System.err;
		    				susp_count++;
		    			}
		    			out.println(line);
				    	if(log!=null) {
				    		log.println(line);
				    	}
		    			hit = true;
		    		}
		    	}
		    	if(hit) {
		    		System.out.println();
		    		log.println();
		    	}
		    	
		    	if(rec!=null) {
		    		rec.println(process);
		    	}
		    	
		    	Thread.sleep(100); // don't send requests too frequently
		    	
		    	csc_failures = 0;
	    		scan_count++;
		    	
	    	} catch(Exception e) {
	    		
	    		e.printStackTrace();
	    		
	    		System.out.println("error scanning process.");
	    		if(++csc_failures>=max_failures) {
	    			System.out.println("aborted: maximum consecutive failures reached");
	    			break;
	    		}
	    		
	    	}
	    }

	    if(log!=null) { log.close(); }
	    if(rec!=null) { rec.close(); }
	}
	
	public PrintWriter getPrintWriter(File file, String name) {
		try {
			return new PrintWriter(new FileWriter(file,true));
		} catch(Exception e) {
			e.printStackTrace();
			System.out.println("error accessing "+name+"...");
		}
		return null;
	}
	
	private static int parseIntWithDefault(String str, int def) {
		try {
			return Integer.parseInt(str);
		} catch(Exception e) {}
		return def;
	}
	
	private static String stripQuotes(String str) {
		if(str.length()>=2 && str.charAt(0)=='"' && str.charAt(str.length()-1)=='"') {
			return str.substring(1,str.length()-1);
		}
		return str;
	}
	
	public static void main(String[] args) {
		
		// default settings
		int max_failures = 3;
		String rec_path = System.getProperty("user.dir")+"/data/scanned.rec";
		String log_path = System.getProperty("user.dir")+"/data/scanned.log";
		boolean show_skip = false;
		
		// handle command-line arguments
		for(int i=0;i<args.length;i++) {
			if(args[i].charAt(0)=='-') {
				int split_ind = args[i].indexOf("=");
				if(split_ind!=-1) {
					String key = args[i].substring(1,split_ind).trim();
					String val = args[i].substring(split_ind+1).trim();
					switch(key) {
						case "max_failures":
							max_failures = Math.max(0,parseIntWithDefault(val,max_failures));
						break;
						case "record_path":
							rec_path = stripQuotes(val);
						break;
						case "log_path":
							log_path = stripQuotes(val);
						break;
					}
				} else {
					String arg = args[i].trim().substring(1);
					switch(arg) {
						case "show_skip":
							show_skip = true;
						break;
						case "help":
							System.out.println("max_failures=[int] - maximum # of consecutive failures until the program aborts.");
							System.out.println("record_path=[string] - location to store a list of previously scanned processes.");
							System.out.println("log_path=[string] - location to store an output log.");
							System.out.println("show_skip - name all skipped processes.");
							System.out.println("help - show this message.");
							System.exit(0);
						break;
					}
				}
			}
		}
		
		/*
		System.out.println("max_failures = "+max_failures);
		System.out.println("record_path = "+rec_path);
		System.out.println("log_path = "+log_path);
		System.out.println("show_skip = "+show_skip);
		System.out.println();
		*/
		
		File rec_file = new File(rec_path); // past scan records
		File log_file = new File(log_path); // diagnostic log
		
		ProcessScanner ps = new ProcessScanner(max_failures,log_file,rec_file);
		ps.setShowSkippedProcess(show_skip);
		ps.scan();
		
		System.out.println();
	    System.out.println("skipped "+ps.getSkipCount()+" process(es)");
	    System.out.println("scanned "+ps.getScanCount()+" process(es)");
	    System.out.println("found "+ps.getSuspiciousCount()+" suspicious process(es)");
	    System.out.println();
	    System.out.println("scan concluded");
	    System.out.println();
	    
	    System.exit(0);
	}
	
}
