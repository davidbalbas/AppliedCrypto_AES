#include "aes.h"

void subWord(unsigned char* word){
  for (int i = 0; i < 4; i++) {
    word[i] = sbox[word[i] / 16][word[i] % 16];
  }
}

void rotWord(unsigned char* word){
  unsigned char temp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = temp;
}

void keyExpansion(unsigned char* key, unsigned char* w) {
  //unsigned char temp[4];
  int i = 0;
  while (i < 16) {
    w[i] = key[i];
    i++;
  }
  i = 4;
  while (i < 44) {
    unsigned char temp[4] = { w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1] };
    if (i % 4 == 0) {
      rotWord(temp);
      subWord(temp);
      temp[0] ^= rcon[i/4];
    }
    w[4*i] = w[4*i-16] ^ temp[0];
    w[4*i+1] = w[4*i-15] ^ temp[1];
    w[4*i+2] = w[4*i-14] ^ temp[2];
    w[4*i+3] = w[4*i-13] ^ temp[3];
    i += 1;
  }
  delete []temp;
}

void addRoundKey(unsigned char state[][4], unsigned char* w) {
  for(int i = 0; i < 16; i++){
    state[i%4][i/4] ^= w[i];
  }
}

void subBytes(unsigned char state[][4]) {
  for(int i = 0; i < 16; i++){
    state[i/4][i%4] = sbox[state[i/4][i%4]/16][state[i/4][i%4]%16];
  }
}

void shiftRows(unsigned char state[][4]) {
  unsigned char temp, temp2;
  //Row 1 (row 0 unchanged)
  temp = state[1][0];
  for(int j = 0; j < 3; j++){
    state[1][j] = state[1][(1+j) % 4];
  }
  state[1][3] = temp;
  //Row 2
  temp = state[2][0];
  temp2 = state[2][1];
  state[2][0] = state[2][2];
  state[2][1] = state[2][3];
  state[2][2] = temp;
  state[2][3] = temp2;
  //Row 3
  temp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = temp;
}

unsigned char mult(unsigned char n, unsigned char m){
  if (n == 0x02) {
    return mul2[m];
  }
  if (n == 0x03) {
    return mul3[m];
  }
  return m;
}

void mixColumns(unsigned char state[][4]) {
  unsigned char c[4], d[4];
  for (int j = 0; j < 4; j++) {
    //Create columns to operate on them
    for (int i = 0; i < 4; i++) {
      c[i] = state[i][j];
    }
    d[0] = mult(0x02, c[0]) ^ mult(0x03, c[1]) ^ c[2] ^ c[3];
    d[1] = c[0] ^ mult(0x02, c[1]) ^ mult(0x03, c[2]) ^ c[3];
    d[2] = c[0] ^ c[1] ^ mult(0x02, c[2]) ^ mult(0x03, c[3]);
    d[3] = mult(0x03, c[0]) ^ c[1] ^ c[2] ^ mult(0x02, c[3]);
    for(int i = 0; i < 4; i++){
      state[i][j] = d[i];
    }
  }
}

unsigned char* aes_encrypt(unsigned char* plaintext, unsigned char* key, unsigned char* ciphertext) {
  // Plaintext, ciphertext and key are arrays unsigned char[16]
  const int ROUNDS = 10;
  unsigned char state[4][4]; //state[i] is a ROW of the matrix. Each column is a WORD.
  unsigned char expKey[176];
  unsigned char w[16 * (ROUNDS + 1)];

  keyExpansion(key, w);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[i][j] = plaintext[i + 4 * j];
    }
  }
  addRoundKey(state, w);

  for (int i = 0; i < ROUNDS - 1; i++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, w + (i+1) * 16);
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, w + ROUNDS * 16);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      ciphertext[i + 4 * j] = state[i][j];
    }
  }
  return ciphertext;
}

int main(int argc, char* argv[]) {
  unsigned char key[16];
  unsigned char plaintext[16];
  unsigned char ciphertext[16];
  char character;

  if (DEBUG) {
    int i = 0;
    while (i < 16 && cin.get(character)) {
      key[i] = character;
      cout << hex << (int) key[i];
      i += 1;
    }
    cout << '\n';
    i = 0;
    while(cin.get(character)){
      plaintext[i] = character;
      cout << hex << (int) plaintext[i];
      i += 1;
      if (i == 16){
        i = 0;
        cout << '\n';
        aes_encrypt(plaintext, key, ciphertext);
        for (int j = 0; j < 16; j++){
          cout << hex << (int) ciphertext[j];
        }
      }
    }
  }

  // DEBUG = TRUE
  else
  {
    int i = 0;
    while (i < 16 && cin.get(character)) {
      key[i] = character;
      i += 1;
    }
    i = 0;
    while(cin.get(character)){
      plaintext[i] = character;
      i += 1;
      if (i == 16){
        i = 0;
        aes_encrypt(plaintext, key, ciphertext);
        for (int j = 0; j < 16; j++){
          cout << ciphertext[j];
        }
      }
    }
  }

  return 0;
}
