using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{

	public class RSA
	{
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

		public int Encrypt(int p, int q, int M, int e)
		{

			int n = p * q;

			int c = M;

			for (int i = 0; i < e - 1; i++)
			{
				c = c * M;

				if (c > n)
				{
					c = c % n;
				}
			}

			return c;
		}

		public int Decrypt(int p, int q, int C, int e)
		{
			int n = p * q;

			int x = (p - 1) * (q - 1);
			int d = GetMultiplicativeInverse(e, x);

			int plain = C;

			for (int i = 0; i < d - 1; i++)
			{
				plain = plain * C;

				if (plain > n)
				{
					plain = plain % n;
				}
			}

			return plain;

		}
	}
}
