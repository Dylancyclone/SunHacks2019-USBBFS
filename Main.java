public class Main {

  public static void main(String[] args) {
    Blockchain blockchain = new Blockchain(1);
    blockchain.addBlock(blockchain.newBlock("First"));
    blockchain.addBlock(blockchain.newBlock("Second"));
    blockchain.addBlock(blockchain.newBlock("Third"));
  
    System.out.println("Blockchain valid ? " + blockchain.isBlockChainValid());
    System.out.println(blockchain);
  }
}