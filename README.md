# Memo DID And Mfile DID Golang SDK

## 介绍

该文档主要介绍如何使用go-did，从而和Memo DID以及Mfile DID的合约进行交互。关于DID的详细信息请查阅[DID文档](https://www.w3.org/TR/did-core/)，关于Memo DID的详细信息请查阅[Memo DID文档](http://132.232.87.203:8088/did/docs/blob/master/memo-did%E8%AE%BE%E8%AE%A1.md)，关于Mfile DID的详细信息请查阅[Mfile DID文档](http://132.232.87.203:8088/did/docs/blob/master/mfile-did%E8%AE%BE%E8%AE%A1.md)。

## 安装

-

## 与Memo DID合约进行交互

在go-did中，提供了`MemoDIDController`类，用于控制合约中保存的Memo DID文档，从而实现对Memo DID权限的控制。目前支持如下链：

- dev：https://devchain.metamemo.one:8501

### 创建DID

创建一个全新的DID。

```go
package main

import (
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
)

func main() {
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDController(sk, "dev")
	if err != nil {
		panic(err.Error())
	}

	err = controller.RegisterDID()
	if err != nil {
		panic(err.Error())
	}

	log.Println(controller.DID())
}
```

### 查看DID文档详细信息

如果DID已经创建，可以查看完整的DID文档。

```go
package main

import (
	"encoding/json"
	"log"

	"github.com/memoio/go-did/memo"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"

	resolver, err := memo.NewMemoDIDResolver("dev")
	if err != nil {
		panic(err.Error())
	}

	document, err := resolver.Resolve(did)
	if err != nil {
		panic(err.Error())
	}

	data, err := json.Marshal(document)
	if err != nil {
		panic(err.Error())
	}

	log.Println(string(data))
}
```

### 添加新的验证方法

可以为一个已有的Memo DID添加新的验证方法。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	err = controller.AddVerificationMethod("EcdsaSecp256k1VerificationKey2019", *DID, "0x02d78b20654eb7a5d58d83b25d090a338eff18f0b5f919777c9d894c2e161b4b52")
	if err != nil {
		panic(err.Error())
	}
}
```

### 修改验证方法

可以修改已有的验证方法

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(1)
	err = controller.UpdateVerificationMethod(didUrl, "EcdsaSecp256k1VerificationKey2019", "0x03d21e6c4843fa3f5d019e551131106e2075925b01da2a83dc177879a512eb608f")
	if err != nil {
		panic(err.Error())
	}
}
```

### 删除验证方法

可以删除已有的验证方法

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(1)
	err = controller.DeactivateVerificationMethod(didUrl)
	if err != nil {
		panic(err.Error())
	}
}
```

### 添加登录验证方法

在创建Memo DID后，可以添加新的登录验证方法，验证方法包括公钥信息等。成功添加后，可以使用对应私钥的签名，以该DID的身份线下登录第三方应用，例如memo中间件。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(0)
	err = controller.AddRelationShip(types.Authentication, didUrl, 0)
	if err != nil {
		panic(err.Error())
	}
}
```

### 删除登录验证方法

可以删除已有的登录方法。删除成功后，使用对应私钥的签名，将不能以该DID的身份线下登录第三方应用。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(0)
	err = controller.DeactivateRelationShip(types.Authentication, didUrl)
	if err != nil {
		panic(err.Error())
	}
}
```

### 添加代理访问验证方法

在创建Memo DID后，可以添加新的代理访问验证方法，验证方法包括公钥信息等。成功添加后，可以使用对应私钥的签名，以该DID的身份访问需要权限的资源，例如，Memo中间件中用户的私有文件。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(0)
	err = controller.AddRelationShip(types.CapabilityDelegation, didUrl, 0)
	if err != nil {
		panic(err.Error())
	}
}
```

### 删除代理访问验证方法

可以删除原有的代理访问验证方法删除成功后，使用对应私钥的签名，将不能以该DID的身份访问需要权限的资源。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	DID, err := types.ParseMemoDID(did)
	if err != nil {
		panic(err.Error())
	}
	didUrl, _ := DID.DIDUrl(0)
	err = controller.DeactivateRelationShip(types.CapabilityDelegation, didUrl)
	if err != nil {
		panic(err.Error())
	}
}
```

### 购买读权限

能够通过付费的方式购买私有文件的读权限。在购买读权限后，会将memo did添加到mfile did的read字段中，从而能够线下请求mfile did对应的文件。在购买读权限之前，需要调用approve方法。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	mfiledid, _ := types.ParseMfileDID("did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4")

	err = controller.ApproveOfMfileContract(1000)
	if err != nil {
		panic(err.Error())
	}

	err = controller.BuyReadPermission(*mfiledid)
	if err != nil {
		panic(err.Error())
	}
}
```

### 删除DID

可以删除已创建的DID。删除后，DID将不可用且该DID将无法重新创建。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/memo"
)

func main() {
	did := "did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := memo.NewMemoDIDControllerWithDID(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	err = controller.DeactivateDID()
	if err != nil {
		panic(err.Error())
	}
}
```

## 与Mfile DID合约进行交互

在go-did中，提供了`MfileDIDController`类，用于控制合约中保存的Mfile DID文档，从而实现对Mfile DID权限的控制。目前支持如下链：

- dev：https://devchain.metamemo.one:8501

### 创建DID

创建一个全新的Mfile DID。

```go
package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	memodid, _ := types.ParseMemoDID("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96")

	err = controller.RegisterDID("mid", 0, big.NewInt(50), []string{"memo", "example"}, *memodid)
	if err != nil {
		panic(err.Error())
	}
}
```

### 更改所有者

Mfile DID的所有者可以通过更改所有者的方式，将Mfile DID实现转让的功能。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	memodid, _ := types.ParseMemoDID("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96")

	err = controller.ChangeController(*memodid)
	if err != nil {
		panic(err.Error())
	}
}
```

### 更改文件类型

Mfile DID对应的文件包括公开文件以及私有文件，可以通过该方法修改文件的类型。其中，0表示private文件，1表示public文件

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	err = controller.ChangeFileType(1)
	if err != nil {
		panic(err.Error())
	}
}
```

### 更改文件的价格

可以修改文件的价格。

```go
package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	err = controller.ChangePrice(big.NewInt(25))
	if err != nil {
		panic(err.Error())
	}
}
```

### 更改文件关键词

文件的关键词用于搜索文件，可以根据需要更改文件的关键词

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	err = controller.ChangeKeywords([]string{"movie", "china"})
	if err != nil {
		panic(err.Error())
	}
}
```

### 授予读取权限

当Mfile DID显示的文件为私有文件时，其他Memo DID的所有者除了购买读权限外，还可以直接授予读取权限。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	memodid, _ := types.ParseMemoDID("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96")

	err = controller.AddRelationShip(types.Read, *memodid)
	if err != nil {
		panic(err.Error())
	}
}
```

### 撤销读取权限

可以撤销之前授予的读取权限，但是无法撤销其他人购买的读取权限。

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
	"github.com/memoio/go-did/types"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	memodid, _ := types.ParseMemoDID("did:memo:d687daa192ffa26373395872191e8502cc41fbfbf27dc07d3da3a35de57c2d96")

	err = controller.DeactivateRelationShip(types.Read, *memodid)
	if err != nil {
		panic(err.Error())
	}
}
```

### 删除DID

可以删除Mfile DID

```go
package main

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/memoio/go-did/mfile"
)

func main() {
	did := "did:mfile:bafkreic7emp2v6ofwkpiiqmrbjq2m6sgyws4eyq5jbphqiywkqyxzbags4"
	sk, err := crypto.GenerateKey()
	if err != nil {
		panic(err.Error())
	}

	controller, err := mfile.NewMfileDIDController(sk, "dev", did)
	if err != nil {
		panic(err.Error())
	}

	err = controller.DeactivateDID()
	if err != nil {
		panic(err.Error())
	}
}
```

