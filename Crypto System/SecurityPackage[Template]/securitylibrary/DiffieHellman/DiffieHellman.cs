using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
	public class DiffieHellman
	{
		public int power(int f, int s, int sf)
		{

			int res = f;

			for (int i = 0; i < s - 1; i++)
			{
				res *= f;

				if (res > sf)
				{
					res %= sf;
				}
			}

			return res;
		}

		public List<int> GetKeys(int q, int alpha, int xa, int xb)
		{
			int keyA = power(alpha, xa, q);
			int keyB = power(alpha, xb, q);

			List<int> keys = new List<int>();

			keys.Add(power(keyB, xa, q));
			keys.Add(power(keyA, xb, q));

			return keys;

		}
	}
}