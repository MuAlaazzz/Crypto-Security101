using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
	public class ElGamal
	{
		/// <summary>
		/// Encryption
		/// </summary>
		/// <param name="alpha"></param>
		/// <param name="q"></param>
		/// <param name="y"></param>
		/// <param name="k"></param>
		/// <returns>list[0] = C1, List[1] = C2</returns>
		/// 
		static public int GetMultiplicativeInverse(int number, int baseN)
		{
			int A1 = 1; int A2 = 0; int A3 = baseN;
			int B1 = 0; int B2 = 1; int B3 = number;
			int Q = 0;
			int T1 = 0; int T2 = 0; int T3 = 0;
			bool flag = false;
			while (true)
			{
				Q = (int)(A3 / B3);
				T1 = A1 - Q * B1; T2 = A2 - Q * B2; T3 = A3 - Q * B3;
				A1 = B1; A2 = B2; A3 = B3;
				B1 = T1; B2 = T2; B3 = T3;

				if (B3 == 1)
				{
					flag = true;
					break;
				}
				if (B3 == 0)
				{
					while (A3 < 0)
					{
						A3 += baseN;
					}
					break;
					//return A3;
				}

			}
			if (flag)
			{
				if ((B2 * number) % baseN == 1)
					return B2;
				while (B2 < 0)
				{
					if ((B2 * number) % baseN == 1)
						return B2;

					B2 += baseN;
				}

				return B2;
			}
			return -1;

		}

		static public int power(int num, int pow, int mod)
		{
			int res = num;

			for (int i = 0; i < pow - 1; i++)
			{
				res *= num;

				if (res > mod)
				{
					res %= mod;
				}
			}

			return res;
		}

		public List<long> Encrypt(int q, int alpha, int y, int k, int m)
		{
			int newK = power(y, k, q);
			int c1 = power(alpha, k, q);
			int c2 = (newK * m) % q;

			List<long> c = new List<long>();

			c.Add(c1);
			c.Add(c2);

			return c;
		}

		public int Decrypt(int c1, int c2, int x, int q)
		{
			int key = power(c1, x, q);
			int d = GetMultiplicativeInverse(key, q);
			int plain = (c2 * d) % q;

			return plain;
		}
	}
}
