#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <iostream>
#include <vector>
#include <bitset>
#include <iomanip>
#include <algorithm>

using namespace std;

typedef std::vector<std::vector<unsigned char>> Matrix;
typedef std::vector<unsigned char> Vector;
using Matrix = std::vector<std::vector<unsigned char>>;

const Matrix A = {
    {1, 0, 0, 0, 1, 1, 1, 1},
    {1, 1, 0, 0, 0, 1, 1, 1},
    {1, 1, 1, 0, 0, 0, 1, 1},
    {1, 1, 1, 1, 0, 0, 0, 1},
    {1, 1, 1, 1, 1, 0, 0, 0},
    {0, 1, 1, 1, 1, 1, 0, 0},
    {0, 0, 1, 1, 1, 1, 1, 0},
    {0, 0, 0, 1, 1, 1, 1, 1}};
const Matrix B = {
    {0, 0, 1, 0, 0, 1, 0, 1},
    {1, 0, 0, 1, 0, 0, 1, 0},
    {0, 1, 0, 0, 1, 0, 0, 1},
    {1, 0, 1, 0, 0, 1, 0, 0},
    {0, 1, 0, 1, 0, 0, 1, 0},
    {0, 0, 1, 0, 1, 0, 0, 1},
    {1, 0, 0, 1, 0, 1, 0, 0},
    {0, 1, 0, 0, 1, 0, 1, 0}};
const Vector c = {1, 1, 0, 0, 0, 1, 1, 0};
const std::bitset<9> mx = 0b100011011;

// Fonction pour convertir un hexadécimal en polynôme dans F_2^8[x]
bitset<32> hex_to_poly(string hex)
{
    bitset<32> poly;
    for (char c : hex)
    {
        poly <<= 4;
        if (c >= '0' && c <= '9')
        {
            poly |= c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            poly |= c - 'A' + 10;
        }
        else if (c >= 'a' && c <= 'f')
        {
            poly |= c - 'a' + 10;
        }
        else
        {
            cerr << "Erreur : caractère hexadécimal invalide" << endl;
            exit(1);
        }
    }
    return poly;
}
std::vector<bool> hex_poly(const std::string &hex)
{
    std::vector<bool> poly;
    for (char c : hex)
    {
        std::bitset<4> bits;
        if (c >= '0' && c <= '9')
        {
            bits = c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            bits = c - 'A' + 10;
        }
        else if (c >= 'a' && c <= 'f')
        {
            bits = c - 'a' + 10;
        }
        else
        {
            std::cerr << "Error: Invalid hexadecimal character" << std::endl;
            exit(1);
        }
        for (int i = 3; i >= 0; i--)
        {
            poly.push_back(bits[i]);
        }
    }
    std::reverse(poly.begin(), poly.end()); // Reverse the vector
    return poly;
}
// Fonction pour calculer le produit de deux polynômes dans F_2^8[x] modulo m(x)
bitset<32> poly_mul(bitset<32> p, bitset<32> q)
{
    bitset<32> r = 0;
    for (int i = 0; i < 32; i++)
    {
        if (q[i] == 1)
        {
            r ^= (p << i);
        }
    }
    for (int i = 31; i >= 8; i--)
    {
        if (r[i] == 1)
        {
            r ^= (mx.to_ulong() << (i - 8));
        }
    }
    return r;
}
// Fonction pour calculer la puissance d'un polynôme dans F_2^8[x] modulo m(x)
bitset<32> poly_pow(bitset<32> p, int n)
{
    bitset<32> r = 1;
    while (n > 0)
    {
        if (n % 2 == 1)
        {
            r = poly_mul(r, p);
        }
        p = poly_mul(p, p);
        n /= 2;
    }
    return r;
}
Vector MatrixVectorProduct(const Matrix &A, const std::vector<bool> &b)
{
    Vector result(A.size(), 0);
    for (int i = 0; i < A.size(); i++)
    {
        for (int j = 0; j < A[i].size(); j++)
        {
            result[i] ^= A[i][j] * b[j];
        }
    }
    for (int i = result.size() - 1; i >= 0; i--)
    {
        result[i] ^= c[i];
    }
    return result;
}
std::vector<bool> PolynomialToBooleanVector(const std::bitset<32> &polynomial)
{
    std::vector<bool> vec;
    for (int i = 0; i <= 7; i++)
    {
        bool bit = polynomial[i];
        vec.push_back(bit);
    }
    return vec;
}
std::string PrintVectorB(const std::vector<bool> &vec)
{
    // Lire les 4 derniers bits dans l'ordre croissant
    int value2 = 8 * vec[7] + 4 * vec[6] + 2 * vec[5] + vec[4];
    // Lire les 4 premiers bits dans l'ordre décroissant
    int value1 = 8 * vec[3] + 4 * vec[2] + 2 * vec[1] + vec[0];

    // Convertir les valeurs hexadécimales en une seule chaîne de caractères
    std::stringstream ss;
    ss << std::hex << std::setw(2) << value2 << value1;
    return ss.str();
};
std::string PrintVector(const Vector &vec)
{
    // Lire les 4 derniers bits dans l'ordre croissant
    int value2 = 8 * vec[7] + 4 * vec[6] + 2 * vec[5] + vec[4];
    // Lire les 4 premiers bits dans l'ordre décroissant
    int value1 = 8 * vec[3] + 4 * vec[2] + 2 * vec[1] + vec[0];
    // Convertir les valeurs hexadécimales en une seule chaîne de caractères
    std::stringstream ss;
    ss << std::hex << std::setw(2) << value2 << value1;
    return ss.str();
}
std::string ToHex(unsigned char value)
{
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value);
    return ss.str();
}
unsigned char invToHex(const std::string &hexValue)
{
    std::istringstream iss(hexValue);
    unsigned int value = 0;
    iss >> std::hex >> value;
    return static_cast<unsigned char>(value);
}
// s-box
unsigned char CalculateMatrixVectorProduct(unsigned char hex)
{
    std::string hexss = ToHex(hex);
    // Convertir hex en bitset<32> poly
    bitset<32> poly = hex_to_poly(hexss);
    // Calculer l'inverse de poly
    bitset<32> inverse = poly_pow(poly, 254);
    // Convertir inverse en vecteur booléen
    std::vector<bool> vec = PolynomialToBooleanVector(inverse);
    // Calculer le produit matrice-vecteur
    Vector result = MatrixVectorProduct(A, vec);
    // Convertir le résultat en hexadécimal
    std::string hexValue = PrintVector(result);
    unsigned char uc = invToHex(hexValue);
    return uc;
}
// MixColumns
unsigned char calculateResult(std::string hexp, unsigned char hexq)
{
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hexq);
    std::string hex = ss.str();
    std::bitset<32> p = hex_to_poly(hexp);
    std::bitset<32> q = hex_to_poly(hex);
    std::bitset<32> result = poly_mul(q, p);
    std::bitset<8> maskedResult = result.to_ulong() & 0xFF;
    return maskedResult.to_ulong();
}
Vector MatrixProductB(const Matrix &A, const std::vector<bool> &b)
{
    Vector result(A.size(), 0);
    for (int i = 0; i < A.size(); i++)
    {
        // Effectuer l'opération XOR entre b[i] et c[i]
        for (int j = 0; j < A[i].size(); j++)
        {
            result[i] ^= A[i][j] * (b[j] ^ c[j]); // Effectuer la multiplication et le XOR avec le résultat partiel
        }
    }
    return result;
};
// invMixColumns
unsigned char invMatrixProductB(unsigned char hex)
{
    std::string hexss = ToHex(hex);
    std::vector<bool> vec = hex_poly(hexss);
    // Calculer le produit matrice-vecteur
    Vector mat = MatrixProductB(B, vec);
    std::string result = PrintVector(mat);
    unsigned char uc = invToHex(result);
    return uc;
}
// invS-Box
unsigned char invS(unsigned char hex)
{
    unsigned char hexa = invMatrixProductB(hex);
    std::string hexss = ToHex(hexa);
    // Convertir hex en bitset<32> poly
    bitset<32> poly = hex_to_poly(hexss);
    // Calculer l'inverse de poly
    bitset<32> inverse = poly_pow(poly, 254);
    // Convertir inverse en vecteur booléen
    std::vector<bool> vec = PolynomialToBooleanVector(inverse);
    std::string result = PrintVectorB(vec);
    unsigned char uc = invToHex(result);
    return uc;
}
// Used in KeyExpansion
unsigned char rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

// Auxiliary function for KeyExpansion
void KeyExpansionCore(unsigned char *in, unsigned char i)
{
    // Rotate left by one byte: shift left
    unsigned char t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;

    // S-box 4 bytes
    in[0] = CalculateMatrixVectorProduct(in[0]);
    in[1] = CalculateMatrixVectorProduct(in[1]);
    in[2] = CalculateMatrixVectorProduct(in[2]);
    in[3] = CalculateMatrixVectorProduct(in[3]);

    // RCon
    in[0] ^= rcon[i];
}

void KeyExpansion(unsigned char inputKey[16], unsigned char expandedKeys[176])
{
    // The first 128 bits are the original key
    for (int i = 0; i < 16; i++)
    {
        expandedKeys[i] = inputKey[i];
    }

    int bytesGenerated = 16;  // Bytes we've generated so far
    int rconIteration = 1;    // Keeps track of rcon value
    unsigned char tmpCore[4]; // Temp storage for core
    while (bytesGenerated < 176)
    {
        for (int i = 0; i < 4; i++)
        {
            tmpCore[i] = expandedKeys[i + bytesGenerated - 4];
        }
        // Perform the core once for each 16 byte key
        if (bytesGenerated % 16 == 0)
        {
            KeyExpansionCore(tmpCore, rconIteration++);
        }
        for (unsigned char a = 0; a < 4; a++)
        {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ tmpCore[a];
            bytesGenerated++;
        }
    }
}

#endif /* STRUCTURES_H */
