
public class GIFTPerm {

	public static void main(String[] args) {
		int bitNum = 32;
		for(int i = 0; i < bitNum; i++)
		{
			System.out.println(i + "->" + permutation(i,bitNum) + " ");
		}

	}
	
	public static int permutation(int i,int bitNum)
	{
		return (left(i) + middle(i,bitNum) + right(i));
	}
	
	public static int left(int i)
	{
		double temp = (double) i/16;
		
		int returnVal = ((int) temp) * 4;
		return returnVal;
	}
	
	public static int middle(int i, int bitNum)
	{
		int returnVal;
		int multNum = (int) (bitNum/4);
		
		int numeratorNum = i%16;
		int fraction = 3*((int)numeratorNum/4);
		fraction = (fraction + (i%4))%4;
		returnVal = fraction * multNum;
			
		return returnVal;
	}
	
	public static int right(int i)
	{
		return (i%4);
	}

}
