# ⚙️ Go-Mal


> A repository for malware projects developed in golang.

## 🚀 Features

- files-encrypted
    - uses AES encryption to encrypt files in current directory of where the main program is run.
    - provided 2 example files
        - normal file: `example.txt`
        - encrypted file: `example.txt.aes` (will be generated after run)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/viperh/go-mal.git

# Navigate into the project directory
cd go-mal

# Navigate to the desired directory

cd <dir-name>

# Install dependencies

go mod tidy

#Run the main program

go run main.go
```

---

# ⚠️ Read the documentation carefully before running the code.

``Info.txt`` contains information about the individual projects and what each does.

I also wrote comments in code for educational purposes. 

---
## Disclaimer

This software is provided for educational and lawful purposes only. The developer assumes no responsibility or 
liability for any misuse, unethical, or illegal activities carried out with this software. By using this software,
you agree that you are solely responsible for your actions and any consequences that may result from its use. 
The developer shall not be held liable for any damage, loss, or legal issues arising from improper use.

---

## License

MIT License

Copyright (c) 2025 [viperh]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
