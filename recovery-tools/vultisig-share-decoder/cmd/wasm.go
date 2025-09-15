//go:build wasm
// +build wasm

package main

import (
        "fmt"
        "io"
        "log"
        "os"
        "syscall/js"
        "main/internal/utils"
        "main/internal/processing"
)

func main() {
    if os.Getenv("ENABLE_LOGGING") != "true" {
        log.SetOutput(io.Discard)
    }
    log.SetFlags(log.Lshortfile | log.LstdFlags)
    log.Println("Starting WASM application...")

    c := make(chan struct{}, 0)

    // JSON-only WASM endpoints

    // ProcessFilesJSON - Process vault files and return JSON
    js.Global().Set("ProcessFilesJSON", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        // args[0] = file contents
        // args[1] = passwords
        // args[2] = filenames
        var fileInfos []utils.FileInfo
        passwords := make([]string, args[1].Length())

        // Convert file data and create FileInfo objects
        for i := 0; i < args[0].Length(); i++ {
            jsArray := args[0].Index(i)
            data := make([]byte, jsArray.Length())
            for j := 0; j < jsArray.Length(); j++ {
                data[j] = byte(jsArray.Index(j).Int())
            }

            // Get the actual filename from the third argument
            filename := args[2].Index(i).String()

            fileInfos = append(fileInfos, utils.FileInfo{
                Name:    filename,
                Content: data,
            })
        }

        // Convert passwords
        for i := 0; i < args[1].Length(); i++ {
            passwords[i] = args[1].Index(i).String()
        }

        // Process the files and return JSON
        result, err := processing.ProcessFileContentJSON(fileInfos, passwords, utils.Web)
        if err != nil {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   err.Error(),
            }
            jsonStr, _ := processing.ToJSON(errorResult)
            return jsonStr
        }

        jsonStr, err := processing.ToJSON(result)
        if err != nil {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   fmt.Sprintf("Error converting to JSON: %v", err),
            }
            fallbackJSON, _ := processing.ToJSON(errorResult)
            return fallbackJSON
        }
        return jsonStr
    }))

    // DeriveAndShowKeysJSON - JSON version of DeriveAndShowKeys
    js.Global().Set("DeriveAndShowKeysJSON", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        if args[0].IsNull() || args[1].IsNull() {
            errorResult := processing.DeriveKeysResult{
                Success: false,
                Error:   "rootPrivateKeyHex and rootChainCodeHex are required",
            }
            jsonStr, _ := processing.ToJSON(errorResult)
            return jsonStr
        }
        
        rootPrivateKeyHex := args[0].String()
        rootChainCodeHex := args[1].String()

        // Check for optional EdDSA keys
        var eddsaPrivateKeyHex, eddsaPublicKeyHex string
        if len(args) >= 4 && !args[2].IsNull() && !args[3].IsNull() {
            eddsaPrivateKeyHex = args[2].String()
            eddsaPublicKeyHex = args[3].String()
        }

        result, err := processing.DeriveAndShowKeysJSON(rootPrivateKeyHex, rootChainCodeHex, eddsaPrivateKeyHex, eddsaPublicKeyHex)
        if err != nil {
            // Error result is already in result struct
            jsonStr, _ := processing.ToJSON(result)
            return jsonStr
        }

        jsonStr, err := processing.ToJSON(result)
        if err != nil {
            errorResult := processing.DeriveKeysResult{
                Success: false,
                Error:   fmt.Sprintf("Error converting to JSON: %v", err),
            }
            fallbackJSON, _ := processing.ToJSON(errorResult)
            return fallbackJSON
        }
        return jsonStr
    }))

    // ProcessDKLSFileContentJSON - Process DKLS files and return structured JSON (same format as GG20)
    js.Global().Set("ProcessDKLSFileContentJSON", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        // args[0] = file contents (array)
        // args[1] = passwords (array)
        // args[2] = filenames (array)
        // args[3] = ecdsaPrivateKeyHex (string)
        // args[4] = rootChainCodeHex (string)
        // args[5] = eddsaPublicKeyHex (string)
        // args[6] = eddsaPrivateKeyHex (string) - NEW!
        
        if len(args) < 7 {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   "ProcessDKLSFileContentJSON requires 7 arguments: files, passwords, filenames, ecdsaPrivateKeyHex, rootChainCodeHex, eddsaPublicKeyHex, eddsaPrivateKeyHex",
            }
            jsonStr, _ := processing.ToJSON(errorResult)
            return jsonStr
        }

        var fileInfos []utils.FileInfo
        passwords := make([]string, args[1].Length())

        // Convert file data and create FileInfo objects
        for i := 0; i < args[0].Length(); i++ {
            jsArray := args[0].Index(i)
            data := make([]byte, jsArray.Length())
            for j := 0; j < jsArray.Length(); j++ {
                data[j] = byte(jsArray.Index(j).Int())
            }

            // Get the actual filename from the third argument
            filename := args[2].Index(i).String()

            fileInfos = append(fileInfos, utils.FileInfo{
                Name:    filename,
                Content: data,
            })
        }

        // Convert passwords
        for i := 0; i < args[1].Length(); i++ {
            passwords[i] = args[1].Index(i).String()
        }

        // Get the key parameters
        ecdsaPrivateKeyHex := args[3].String()
        rootChainCodeHex := args[4].String()
        eddsaPublicKeyHex := args[5].String()
        eddsaPrivateKeyHex := args[6].String()

        // Process the DKLS files and return JSON
        result, err := processing.ProcessDKLSFileContentJSON(fileInfos, passwords, ecdsaPrivateKeyHex, rootChainCodeHex, eddsaPublicKeyHex, eddsaPrivateKeyHex)
        if err != nil {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   err.Error(),
            }
            jsonStr, _ := processing.ToJSON(errorResult)
            return jsonStr
        }

        jsonStr, err := processing.ToJSON(result)
        if err != nil {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   fmt.Sprintf("Error converting to JSON: %v", err),
            }
            fallbackJSON, _ := processing.ToJSON(errorResult)
            return fallbackJSON
        }
        return jsonStr
    }))

    // GetSupportedCoinsJSON - JSON version of GetSupportedCoins
    js.Global().Set("GetSupportedCoinsJSON", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        result := processing.ConvertSupportedCoinsToJSON()
        
        jsonStr, err := processing.ToJSON(result)
        if err != nil {
            errorResult := processing.GetSupportedCoinsResult{
                Success: false,
                Error:   fmt.Sprintf("Error converting to JSON: %v", err),
            }
            fallbackJSON, _ := processing.ToJSON(errorResult)
            return fallbackJSON
        }
        return jsonStr
    }))

    log.Println("WASM initialization complete, waiting for JS calls...")
    <-c
}
