//go:build wasm
// +build wasm

package main

import (
        "log"
        "syscall/js"
        "os"
        "io"
        "encoding/hex"
        "strings"
        "main/internal/utils"
        "main/internal/processing"
        "fmt"
)

func main() {
    if os.Getenv("ENABLE_LOGGING") != "true" {
        log.SetOutput(io.Discard)
    }
    log.SetFlags(log.Lshortfile | log.LstdFlags)
    log.Println("Starting WASM application...")

    c := make(chan struct{}, 0)

    js.Global().Set("ProcessFiles", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        // args[0] = file contents
        // args[1] = passwords
        // args[2] = filenames
        // args[3] = scheme (optional)
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

        // Process the files with thresholds
        result, err := processing.ProcessFileContent(fileInfos, passwords, utils.Web)
        if err != nil {
            return err.Error()
        }
        return result
    }))

    // DeriveAndShowKeys - takes DKLS-extracted root key and derives keys for all supported coins
    js.Global().Set("DeriveAndShowKeys", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        if args[0].IsNull() || args[1].IsNull() {
            return "Error: rootPrivateKeyHex and rootChainCodeHex are required"
        }
        
        rootPrivateKeyHex := args[0].String()
        rootChainCodeHex := args[1].String()

        // Decode hex strings
        rootPrivateKeyBytes, err := hex.DecodeString(rootPrivateKeyHex)
        if err != nil {
            return fmt.Sprintf("Error decoding private key hex: %v", err)
        }

        rootChainCodeBytes, err := hex.DecodeString(rootChainCodeHex)
        if err != nil {
            return fmt.Sprintf("Error decoding chain code hex: %v", err)
        }

        var outputBuilder strings.Builder

        // Get ECDSA supported coins and process them
        ecdsaCoins := processing.GetSupportedCoins()
        err = processing.ProcessRootKeyForCoins(rootPrivateKeyBytes, rootChainCodeBytes, ecdsaCoins, &outputBuilder)
        if err != nil {
            return fmt.Sprintf("Error processing ECDSA keys: %v", err)
        }

        // Check if EdDSA keys are available (args[2] and args[3] should be EdDSA private and public key)
        if len(args) >= 4 && !args[2].IsNull() && !args[3].IsNull() {
            eddsaPrivateKeyHex := args[2].String()
            eddsaPublicKeyHex := args[3].String()
            
            eddsaPrivateKeyBytes, err := hex.DecodeString(eddsaPrivateKeyHex)
            if err != nil {
                return fmt.Sprintf("Error decoding EdDSA private key hex: %v", err)
            }
            
            eddsaPublicKeyBytes, err := hex.DecodeString(eddsaPublicKeyHex)
            if err != nil {
                return fmt.Sprintf("Error decoding EdDSA public key hex: %v", err)
            }

            // Get EdDSA coins and process them
            eddsaCoins := processing.GetEdDSACoins()
            err = processing.ProcessEdDSAKeyForCoins(eddsaPrivateKeyBytes, eddsaPublicKeyBytes, eddsaCoins, &outputBuilder)
            if err != nil {
                return fmt.Sprintf("Error processing EdDSA keys: %v", err)
            }
        }

        return outputBuilder.String()
    }))

    // DeriveSpecificKey - derives a single coin's key
    js.Global().Set("DeriveSpecificKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        if args[0].IsNull() || args[1].IsNull() || args[2].IsNull() {
            return "Error: rootPrivateKeyHex, rootChainCodeHex, and coinType are required"
        }
        
        rootPrivateKeyHex := args[0].String()
        rootChainCodeHex := args[1].String()
        coinType := args[2].String()

        // Decode hex strings
        rootPrivateKeyBytes, err := hex.DecodeString(rootPrivateKeyHex)
        if err != nil {
            return fmt.Sprintf("Error decoding private key hex: %v", err)
        }

        rootChainCodeBytes, err := hex.DecodeString(rootChainCodeHex)
        if err != nil {
            return fmt.Sprintf("Error decoding chain code hex: %v", err)
        }

        // Find the specific coin configuration
        supportedCoins := processing.GetSupportedCoins()
        var targetCoin *processing.CoinConfig
        for _, coin := range supportedCoins {
            if coin.Name == coinType {
                targetCoin = &coin
                break
            }
        }

        if targetCoin == nil {
            return fmt.Sprintf("Error: unsupported coin type: %s", coinType)
        }

        // Process the root key for the specific coin
        var outputBuilder strings.Builder
        err = processing.ProcessRootKeyForCoins(rootPrivateKeyBytes, rootChainCodeBytes, []processing.CoinConfig{*targetCoin}, &outputBuilder)
        if err != nil {
            return fmt.Sprintf("Error processing key for %s: %v", coinType, err)
        }

        return outputBuilder.String()
    }))

    // GetSupportedCoins - returns list of supported cryptocurrencies
    js.Global().Set("GetSupportedCoins", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
        supportedCoins := processing.GetSupportedCoins()
        
        // Convert to JavaScript array
        result := make([]interface{}, len(supportedCoins))
        for i, coin := range supportedCoins {
            coinData := map[string]interface{}{
                "name":       coin.Name,
                "derivePath": coin.DerivePath,
            }
            result[i] = coinData
        }
        
        return result
    }))

    // JSON-enabled versions of the functions

    // ProcessFilesJSON - JSON version of ProcessFiles
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
        // args[3] = privateKeyHex (string)
        // args[4] = rootChainCodeHex (string)
        // args[5] = eddsaPublicKeyHex (string)
        
        if len(args) < 6 {
            errorResult := processing.ProcessResult{
                Success: false,
                Error:   "ProcessDKLSFileContentJSON requires 6 arguments: files, passwords, filenames, privateKeyHex, rootChainCodeHex, eddsaPublicKeyHex",
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
        privateKeyHex := args[3].String()
        rootChainCodeHex := args[4].String()
        eddsaPublicKeyHex := args[5].String()

        // Process the DKLS files and return JSON
        result, err := processing.ProcessDKLSFileContentJSON(fileInfos, passwords, privateKeyHex, rootChainCodeHex, eddsaPublicKeyHex)
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
