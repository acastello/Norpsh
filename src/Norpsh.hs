import Control.Monad
import Network.Socket
import qualified Network.Socket.ByteString as B
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char
-- import Data.ByteArray hiding (concat)

import System.Directory 
import System.IO

import Text.Read
import Text.Printf

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types
import Crypto.Error

conn :: IO Socket
conn = do
    addri:_ <- getAddrInfo Nothing (Just "norpushy.ddns.net") (Just "12345")
    sock <- socket (addrFamily addri) (addrSocketType addri) (addrProtocol addri)
    connect sock (addrAddress addri)
    return sock

withSock :: (Socket -> IO a) -> IO a
withSock op = do
    sock <- conn
    ret <- op sock
    close sock
    return ret

newtype NorKey = NorKey (ByteString, ByteString, ByteString)
  deriving Show

instance Read NorKey where
    readPrec = do
        s1 <- B.pack <$> anystr
        skipsp
        s2 <- B.pack <$> anystr
        skipsp
        s3 <- B.pack <$> anystr
        return $ NorKey (s1, s2, s3)
            where
                anystr = liftM2 (:) get anystr +++ return ""
                skipsp = replicateM_ 3 (do ; ' ' <- get ; return ())

keyFile :: IO String
keyFile = do
    home <- getHomeDirectory
    let dirs = [filename, concat [home, "/", filename]]
    snd <$> foldM fold (False, "") dirs
    where filename = "norpsh_client_key"
          fold (True, x) _ = return (True, x)
          fold (False, _) file = liftM2 (,) (doesFileExist file) (return file)

retrieveKey :: IO NorKey
retrieveKey = keyFile >>= \f -> read <$> rdfile f where
    rdfile file = do
        h <- openFile file ReadMode
        hSetEncoding h latin1
        conts <- hGetContents h
        length conts `seq` hClose h
        return conts

keyAuth :: NorKey -> ByteString
keyAuth (NorKey (k, u, i)) = B.concat ["cli ", u, " ", i]

connect' = do
    key @ (NorKey (aes, _, _)) <- retrieveKey
    succ <- withSock $ \sock -> do
        B.send sock (keyAuth key)
        (== "OK") <$> B.recv sock 1024
    return succ
    when succ $ withSock $ \sock -> do
        cryptoSend sock aes "id"
        print =<< cryptoRecv sock aes
        shutdown sock ShutdownBoth

encrypt :: ByteString -> ByteString -> ByteString
encrypt secret = ctrCombine ctx (nullIV `ivAdd` 1)
  where
    ctx = cipherInitNoErr secret
    cipherInitNoErr :: ByteString -> AES256
    cipherInitNoErr k = case cipherInit k of
      CryptoPassed a -> a
      CryptoFailed e -> error (show e)

cryptoSend :: Socket -> ByteString -> ByteString -> IO Int
cryptoSend sock aes msg = do
    B.send sock (encrypt aes msg)

cryptoRecv :: Socket -> ByteString -> IO ByteString
cryptoRecv sock aes = do
    encrypt aes <$> B.recv sock 4096
