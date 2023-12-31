from itertools import product

def hash_attempt_lowercase(target_hash):
    hex_chars = '0123456789abcdef'

    results = []

    def recursive_attempt(four_char_hash, letters, i):
        if i == 0:
            for new_lowercase_letter in range(ord('a'), ord('z') + 1):  # Lowercase range
                new_current_hash = 0xbeef ^ (0xffff & ((new_lowercase_letter * 0xCAFEBABE) ^ (0xFACE * i)))

                if new_current_hash == four_char_hash:
                    # print("Found a recursive match")

                    print("FOUND SOME BEEF\n")
                    new_letters = letters + [chr(new_lowercase_letter)]
                    print(f"Debug: new_letters = {new_letters}")
                    results.append((four_char_hash, new_letters, i - 1))
                    return results
        elif i > 0:
            for suffix in product(hex_chars, repeat=4):
                generated_hash = int(''.join(suffix), 16)

                for new_lowercase_letter in range(ord('a'), ord('z') + 1):
                    calculated_hash = generated_hash ^ (0xffff & ((new_lowercase_letter * 0xCAFEBABE) ^ (0xFACE * i)))

                    if calculated_hash == four_char_hash:
                        # if chr(new_lowercase_letter) == 'o' and letters[0] == 'm':
                        #     print("The correct one")

                        new_letters = letters + [chr(new_lowercase_letter)]
                        results.append((calculated_hash, new_letters, i))
                        # print(f"Debug RECURSION: i = {i}, letters = {chr(lowercase_letter)}")
                        recursive_attempt(generated_hash, new_letters.copy(), i - 1)

    
    for suffix in product(hex_chars, repeat=4):
        four_char_hash = int(''.join(suffix), 16)

        for lowercase_letter in range(ord('a'), ord('z') + 1):
            for i in range(25, 26):  # You may adjust the range for the length 'i'
                current_hash = four_char_hash ^ (0xffff & ((lowercase_letter * 0xCAFEBABE) ^ (0xFACE * i)))

                if current_hash == target_hash:
                    # print(f"Debug: i = {i}, letters = {chr(lowercase_letter)}")
                    # results.append((four_char_hash, [chr(lowercase_letter)], i))
                    # recursive_attempt(four_char_hash,[chr(lowercase_letter)],i - 1)
                    # if chr(lowercase_letter) == 'm':
                    #     print("The correct one")

                    new_letters = [chr(lowercase_letter)]
                    results.append((four_char_hash, new_letters, i))
                    # print(f"Debug NO RECURSION: i = {i}, letters = {chr(lowercase_letter)}")
                    recursive_attempt(four_char_hash, new_letters.copy(), i - 1)
                
    return results


def main():
    results = hash_attempt_lowercase(0xfe61)
    
    filtered_results = [result for result in results if result[2] == -1]

    print(filtered_results)

if __name__ == "__main__":
    main()