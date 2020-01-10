package ieeta.aot;

public class Authorization {
  public static class Data {
    
  }
  
  private final Data data;
  
  Authorization(Data data) {
    this.data = data;
    //TODO: add CC signature
  }
}