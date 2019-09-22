package com.lathrum;

import java.io.*;
import java.nio.file.*;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;

import com.lathrum.USBBFS.*;

public class App {

	public static String workingDirectory;
	public static String watchDirectory;
	public static Gson gson = new Gson();
	public static Blockchain blockchain;
	public static WatchService watchService;

	public static String formatPath(String res) {
		if (res == null)
			return null;
		if (File.separatorChar == '\\') {
			// From Windows to Linux/Mac
			return res.replace('/', File.separatorChar);
		} else {
			// From Linux/Mac to Windows
			return res.replace('\\', File.separatorChar);
		}
	}

	private static Blockchain readDataFile() {

		Blockchain blockchain = new Blockchain(4);

		// Open file
		File workingFile = new File(workingDirectory + "/data.txt");
		if (!workingFile.exists()) {
			try {
				File directory = new File(workingFile.getParent());
				if (!directory.exists()) {
					directory.mkdirs();
				}
				workingFile.createNewFile();
			} catch (IOException e) {
				System.out.println("Excepton Occured: " + e.toString());
			}
		}

		// Read File
		InputStreamReader isReader;
		try {
			isReader = new InputStreamReader(new FileInputStream(workingFile), "UTF-8");

			JsonReader myReader = new JsonReader(isReader);
			Blockchain data = gson.fromJson(myReader, Blockchain.class);
			if (data != null) {
				blockchain = data;
			}

		} catch (Exception e) {
			System.out.println("Error load cache from file " + e.toString());
		}
		return blockchain;
	}

	private static void writeDataFile(Blockchain blockchain) {

		// Open file
		File workingFile = new File(workingDirectory + File.separator + "data.txt");
		if (!workingFile.exists()) {
			try {
				File directory = new File(workingFile.getParent());
				if (!directory.exists()) {
					directory.mkdirs();
				}
				workingFile.createNewFile();
			} catch (IOException e) {
				System.out.println("Excepton Occured: " + e.toString());
			}
		}

		// Write file
		try {
			FileWriter writer = new FileWriter(workingFile.getAbsoluteFile(), false);
			writer.write(gson.toJson(blockchain));
			writer.close();

			// System.out.println("\nData saved at file location: " +
			// workingDirectory+File.separator+"data.txt" + " Data: " +
			// gson.toJson(blockchain) + "\n");
			System.out.println("File sucessfully saved");
		} catch (IOException e) {
			System.out.println("Error while saving data to file " + e.toString());
		}
	}

	private static String hash(String data) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");

		final byte bytes[] = digest.digest(data.getBytes());
		final StringBuilder builder = new StringBuilder();

		for (final byte b : bytes) {
			String hex = Integer.toHexString(0xff & b);

			if (hex.length() == 1) {
				builder.append('0');
			}

			builder.append(hex);
		}
		return builder.toString();
	}

	public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException {

		Runtime.getRuntime().addShutdownHook(new Thread() {
			public void run() {
				System.out.println("\n\nShutting Down...");
				try {
					watchService.close();
				} catch (IOException e) {
					System.out.println("Exception while closing watchService: "+ e);
				}
				//System.out.println(blockchain);
				writeDataFile(blockchain);
				for (final File fileEntry : new File(watchDirectory).listFiles()) {
					System.out.println(fileEntry.getPath());

					String hash = blockchain.findBlockHash(fileEntry.getName());
						if (hash == null) {
						} else {
							try {
								
								//encrypt file as program shuts down
								String content = new String(Files.readAllBytes(fileEntry.toPath()));

								byte[] hash32 = new byte[32];
								System.arraycopy(hash.getBytes(), 0, hash32, 0, 32);
								Key aesKey = new SecretKeySpec(hash32, "AES");
								Cipher cipher = Cipher.getInstance("AES");

								cipher.init(Cipher.ENCRYPT_MODE, aesKey);
								byte[] encrypted = cipher.doFinal(content.getBytes());
								Files.write(fileEntry.toPath(), encrypted);
							}
							catch (Exception e) {
								System.out.println("Exception while encrypting: "+ e);
							}
						}
				}
			}
		});

		Path currentRelativePath = Paths.get("");
		workingDirectory = currentRelativePath.toAbsolutePath().toString();
		//System.out.println(workingDirectory);

		if (args.length != 1) {
			System.err.println("Usage: java USBBFS <WatchingDirectory>");
			return;
		}
		watchDirectory = args[0];
		//System.out.println(watchDirectory);
		File watchDir = new File(watchDirectory);
		try {
			if (!watchDir.exists()) {
				watchDir.mkdirs();
			}
		} catch (Exception e) {
			System.out.println("Excepton Occured: " + e.toString());
		}

		blockchain = readDataFile();
		System.out.println(blockchain);

		//Initialize
		if (blockchain.getNumberOfBlocks() == 1) { //Brand new chain
			for (File fileEntry : new File(watchDirectory).listFiles()) {
				String content = new String(Files.readAllBytes(fileEntry.toPath()));
				String hash = hash(content);
				blockchain.addBlock(blockchain.newBlock(fileEntry.getName(),hash));

				System.out.println(fileEntry.getName());

				//Open file
				File workingFile = new File(workingDirectory+File.separator+"blob"+File.separator+fileEntry.getName());
				if (!workingFile.exists()) {
					try {
						File directory = new File(workingFile.getParent());
						if (!directory.exists()) {
							directory.mkdirs();
						}
						workingFile.createNewFile();
					} catch (IOException e) {
						System.out.println("Excepton Occured: " + e.toString());
					}
				}
				Files.copy(fileEntry.toPath(), new File(workingDirectory+File.separator+"blob"+File.separator+fileEntry.getName()).toPath(), StandardCopyOption.REPLACE_EXISTING);
			}
		}
		else
		{ //If this isn't first time set up
			ArrayList<String> files = new ArrayList<String>();

			for (File fileEntry : new File(watchDirectory).listFiles()) {
				files.add(fileEntry.getName());
				String hash = blockchain.findBlockHash(fileEntry.getName());
				String dataHash = blockchain.findBlockData(fileEntry.getName());
				if (hash == null) {
					Files.delete(fileEntry.toPath()); //Delete new file
				}
				else
				{
					try {
						String content = new String(Files.readAllBytes(fileEntry.toPath()));

						byte[] hash32 = new byte[32];
						System.arraycopy(hash.getBytes(), 0, hash32, 0, 32);
						Key aesKey = new SecretKeySpec(hash32, "AES");
						Cipher cipher = Cipher.getInstance("AES");

						cipher.init(Cipher.DECRYPT_MODE, aesKey);
						byte[] decrypted = cipher.doFinal(content.getBytes());
						Files.write(fileEntry.toPath(), decrypted);

						//compare
						if (dataHash.equals(hash(new String(decrypted)))) {
							//compares hashes after decryption. If files on computer have been modified, USB file replaces it. 
						} else { 
							Files.copy(new File(workingDirectory+File.separator+"blob"+File.separator+fileEntry.getName()).toPath(), fileEntry.toPath(), StandardCopyOption.REPLACE_EXISTING);
						}
					}
					catch (Exception e)
					{
						System.out.println("Exception while decrypting: "+ e);
						Files.copy(new File(workingDirectory+File.separator+"blob"+File.separator+fileEntry.getName()).toPath(), fileEntry.toPath(), StandardCopyOption.REPLACE_EXISTING);
					}
				}
			}
			
			for (File fileEntry : new File(workingDirectory+File.separator+"blob"+File.separator).listFiles()) {
				if(files.contains(fileEntry.getName())) {continue;} //I've been in this place before
				Files.copy(fileEntry.toPath(), new File(watchDirectory+File.separator+fileEntry.getName()).toPath(), StandardCopyOption.REPLACE_EXISTING);
			}
		}
		/*byte[] cipherText = Files.readAllBytes(Paths.get(fileName));

		aesCipher.init(Cipher.DECRYPT_MODE, secKey);
		byte[] bytePlainText = aesCipher.doFinal(cipherText);
		Files.write(Paths.get(fileName), bytePlainText); */

		System.out.println();
		System.out.println("Setting up watchers...");
		
		watchService = FileSystems.getDefault().newWatchService();

		final Path workingDir = Paths.get(formatPath(watchDirectory));
		workingDir.register(watchService, StandardWatchEventKinds.ENTRY_DELETE, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE);
		while (true) {
			try {
				final WatchKey watchKey = watchService.take();
				final Watchable watchable = watchKey.watchable();

				if (!(watchable instanceof Path)) {
						throw new AssertionError("The watchable should have been a Path");
				}

				final Path dir = (Path) watchable;
				for (WatchEvent<?> event : watchKey.pollEvents()) {
					System.out.println("Received event '" + event.kind()+ "' for entry '" + event.context()+"'");
					switch (event.kind().toString()) {
						case("ENTRY_MODIFY"):
						case("ENTRY_CREATE"):
							String content = new String(Files.readAllBytes(Paths.get(formatPath(watchDirectory+File.separator+event.context().toString()))));
							String hash = hash(content);
							blockchain.addBlock(blockchain.newBlock(event.context().toString(),hash));

							//Open file
							File workingFile = new File(workingDirectory+File.separator+"blob"+File.separator+event.context().toString());
							if (!workingFile.exists()) {
								try {
									File directory = new File(workingFile.getParent());
									if (!directory.exists()) {
										directory.mkdirs();
									}
									workingFile.createNewFile();
								} catch (IOException e) {
									System.out.println("Excepton Occured: " + e.toString());
								}
							}
							Files.copy(Paths.get(formatPath(watchDirectory+File.separator+event.context().toString())), new File(workingDirectory+File.separator+"blob"+File.separator+event.context().toString()).toPath(), StandardCopyOption.REPLACE_EXISTING);
							break;

						case("ENTRY_DELETE"):
							blockchain.addBlock(blockchain.newBlock(event.context().toString(),null));
							Files.delete(Paths.get(formatPath(workingDirectory+File.separator+"blob"+File.separator+event.context().toString())));
							break;
					}
				}
				watchKey.reset();
				//System.out.println(blockchain);
				writeDataFile(blockchain);
				System.out.println("Listening...");
			} catch (Exception e) {/*hah like you have power here*/}
		}

    //Blockchain blockchain = new Blockchain(4);
    //blockchain.addBlock(blockchain.newBlock("First",null));
		//blockchain.addBlock(blockchain.newBlock("Second",null));
    //blockchain.addBlock(blockchain.newBlock("Third",null));

    //System.out.println("Blockchain valid ? " + blockchain.isBlockChainValid());
		//System.out.println(blockchain);
		

		//writeDataFile(blockchain);
  }

}
