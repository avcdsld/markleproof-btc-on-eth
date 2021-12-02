const crypto = require('crypto')

const LE = (bufBE) => {
    const res = new Array(32)
    for (let i = 0, j = 31; i < bufBE.length; i += 2, j--) {
        res[j] = parseInt(bufBE[i] + bufBE[i + 1], 16)
    }
    return Buffer.from(res)
}

const hexStrBE = (bufLE) => {
    let res = ''
    for (let i = bufLE.length - 1; i >= 0; i--) {
        const digits = bufLE[i].toString(16)
        res += ('0' + digits).slice(-2)
    }
    return res
}

const sha256 = (buf) => {
    return crypto.createHash('SHA256').update(buf).digest()
}

const merkleTree = []

const getMerkleRoot = (txHashes, callback) => {
    merkleTree[merkleTree.length] = txHashes
    if (txHashes.length === 1) {
        return callback('', hexStrBE(txHashes[txHashes.length - 1]))
    }
    if (txHashes.length % 2 != 0) {
        txHashes[txHashes.length] = txHashes[txHashes.length - 1]
    }
    const merkleLeaves = [];
    for (let i = 0, j = 0; i < txHashes.length; i += 2, j++) {
        const concatenated = Buffer.concat([txHashes[i], txHashes[i + 1]])
        merkleLeaves[j] = sha256(sha256(concatenated))
    }
    getMerkleRoot(merkleLeaves, callback)
}

const generateProof = (merkleTree, txHash, callback) => {
    const proof = []
    for (let i = 0; i < merkleTree.length - 1; i++) {
        for (let j = 0; j < merkleTree[i].length; j += 2) {
            if (merkleTree[i][j].equals(txHash) || merkleTree[i][j + 1].equals(txHash)) {
                const proofNode = {
                    hash: merkleTree[i][j].equals(txHash) ? merkleTree[i][j + 1] : merkleTree[i][j],
                    even: merkleTree[i][j].equals(txHash) ? true : false
                }
                proof[proof.length] = proofNode
                txHash = sha256(sha256(Buffer.concat([merkleTree[i][j], merkleTree[i][j + 1]])))
                break
            }
        }
    }
    callback(proof)
}

const main = async () => {
    const block = require('./700004.json')
    const txHashes = [];
    for (const tx of block.tx) {
        txHashes.push(
            LE(tx.hash)
        )
    }
    // console.log(txHashes)

    console.log('TxHash:', txHashes[1].toString('hex'))

    getMerkleRoot(txHashes, (error, body) => {
        console.log('MarkleRoot:', body)
    })

    console.log('MarkleProof:')
    generateProof(merkleTree, txHashes[1], (res) => {
        for (const r of res) {
            console.log(r.hash.toString('hex'))
        }
    })
}

main()
