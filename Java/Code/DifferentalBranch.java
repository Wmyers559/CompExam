
public class DifferentalBranch {
	
	private static final int[] base3Valid = {0,1,2,4,5,6,8,9,0xa};
	private static int[] recursionSbox;
	private static boolean[] vacant;
	private static int counterOfDiffBranch;

	public static void main(String[] args) {
		/*
		int[] presentSBox = {0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2};
		System.out.println("PRESENT SBox Differental Branch Number: " + calculateDifferentalBranch(presentSBox));
		
		int[] giftSBox = {0x1,0xa,0x4,0xc,0x6,0xf,0x3,0x9,0x2,0xd,0xb,0x7,0x5,0x0,0x8,0xe};
		System.out.println("GIFT SBox Differental Branch Number: " + calculateDifferentalBranch(giftSBox));
		*/
		//int[] base3Sbox =  { 0xa, 4, 1, 0xf, 5, 2, 9, 0xf, 6, 0, 8, 0xf, 0xf, 0xf, 0xf, 0xf };
		//System.out.println(baseThreeDifferentalBranch(base3Sbox));
		
		vacant = new boolean[9];
		for(int i = 0; i < vacant.length; i++)
		{
			vacant[i] = true;
		}
		recursionSbox = new int[16];
		for(int i = 0; i < 16; i ++)
		{
			recursionSbox[i] = 0xf;
		}
		counterOfDiffBranch = 0;
		
		base3Pow2Recursion(0);
		
		System.out.println("Found = " + counterOfDiffBranch);
	}
	
	public static void base3Pow2Recursion(int index)
	{
		if(index == (vacant.length-1) )
		{
			for(int i = 0; i < vacant.length; i++)
			{
				if( vacant[i] == true)
				{
					recursionSbox[base3Valid[index]] = base3Valid[i];
					
					if(baseThreeDifferentalBranch(recursionSbox) > 2)
					{
						System.out.println("Found Differantal Branch of " + baseThreeDifferentalBranch(recursionSbox));
						System.out.println(sBoxBase3ToString(recursionSbox));
						counterOfDiffBranch++;
						return;
					}
				}
			}
			return;
		}
		else
		{
			for(int i = 0; i < vacant.length; i++)
			{
				if(vacant[i] == true)
				{
					recursionSbox[base3Valid[index]] = base3Valid[i];
					vacant[i] = false;
					base3Pow2Recursion(index + 1);
					vacant[i] = true;
				}
			}
		}
	}
	
	public static int calculateDifferentalBranch(int [] arr)
	{
		int n = arr.length;
		int branchNumber = arr.length;
		
		for(int i = 0; i < n; i++)
		{
			int initalIn = i;
			int initalOut = arr[i];
			
			for(int j = 0; j < n; j++)
			{
				if(i != j)
				{
					int afterIn = j;
					int afterOut = arr[j];
					
					int inXor = initalIn ^ afterIn;
					int outXor = initalOut ^ afterOut;
					
					int tempDiffNumber = hammingWeight(inXor) + hammingWeight(outXor);
					
					if(tempDiffNumber < branchNumber)
					{
						branchNumber = tempDiffNumber;
					}
				}
				
			}
		}
		return branchNumber;
	}
	
	public static int baseThreeDifferentalBranch(int[] Sbox)
	{
		
		int min = Sbox.length;
		
		for(int i = 0; i < base3Valid.length; i++)
		{
			for(int j = 0; j < base3Valid.length; j++)
			{
				if(i != j)
				{
					int count = 0;
					int[] iVector = numToVectorBase3Pow2(base3Valid[i]);
					int[] jVector = numToVectorBase3Pow2(base3Valid[j]);
					
					int[] iOutVector = numToVectorBase3Pow2(Sbox[base3Valid[i]]);
					int[] jOutVector = numToVectorBase3Pow2(Sbox[base3Valid[j]]);
					
					count += baseThreeWeightVecotr(iVector, jVector);
					count += baseThreeWeightVecotr(iOutVector, jOutVector);
					
					if(count < min)
						min = count;
				}
			}
		}
		
		
		return min;
	}
	
	public static int hammingWeight(int num)
	{
		int count = 0;
		
		for(int i = 0; i < 32; i++)
		{
			if ( ((num >> i)& 1) == 1)
			{
				count++;
			}
		}
		return count;
	}
	
	public static int baseThreeWeight(int num1, int num2)
	{
		if (num1 == num2)
			return 0;
		else
			return 1;
	}
	
	public static int baseThreeWeightVecotr(int[] arr1,int[] arr2)
	{
		int count = 0;
		
		for(int i = 0; i < arr1.length; i++)
		{
			count += baseThreeWeight(arr1[i] , arr2[i]);
		}
		
		return count;
	}
	
	public static int[] numToVectorBase3Pow2(int num)
	{
		int[] returnVal = new int[2];
		returnVal[0] = (num & 0b11);
		returnVal[1] = ( (num >> 2) & 0b11);
		
		return returnVal;
	}
	
	static String sBoxBase3ToString(int[] sBox)
	{
		String returnVal = "";
		for(int i = 0; i < base3Valid.length; i++)
		{
			returnVal = returnVal + base3Valid[i] + " -> " + sBox[base3Valid[i]] + "    ";
		}
		return returnVal;
	}

}
