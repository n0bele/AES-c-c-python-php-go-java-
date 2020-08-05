<?php
class MyCrypt {

    /**
     * [$cipher 加密模式]
     * @var [type]
     */
    private $cipher = MCRYPT_RIJNDAEL_128;
    private $mode = MCRYPT_MODE_CBC;

    /**
     * [$key 密匙]
     * @var string
     */
    private $secret_key = 'wodeshijiehenmei';
    /**
     * [$iv 偏移量]
     * @var string
     */
    private $iv = '010101012345abcd';

    function setCipher($cipher=''){
        $cipher && $this->cipher = $cipher;
    }

    function setMode($mode=''){
        $mode && $this->mode = $mode;
    }

    function setSecretKey($secret_key=''){
        $secret_key && $this->secret_key = $secret_key;
    }

    function setIv($iv=''){
        $iv && $this->iv = $iv;
    }

    //加密
    function encrypt($str)
    {       
        $size = mcrypt_get_block_size ( MCRYPT_RIJNDAEL_128,MCRYPT_MODE_CBC);
        $str = $this->pkcs5Pad( $str, $size );
        //$data=mcrypt_cbc(MCRYPT_RIJNDAEL_128, $this->secret_key, $str, MCRYPT_ENCRYPT, $this->iv);
		$data =  mcrypt_encrypt(MCRYPT_RIJNDAEL_128,$this->secret_key, $str, MCRYPT_MODE_CBC,$this->iv);
        //bin2hex() 函数把 ASCII 字符的字符串转换为十六进制值
        $data=strtoupper(bin2hex($data));
        return $data;
    }

    //解密
    function decrypt($str)
    {
        $str = $this->hex2bin( strtolower($str));
        //$str = mcrypt_cbc(MCRYPT_RIJNDAEL_128, $this->secret_key, $str, MCRYPT_DECRYPT, $this->iv );
		$str = mcrypt_decrypt(MCRYPT_RIJNDAEL_128,$this->secret_key,$str, MCRYPT_MODE_CBC,$this->iv);
        $str = $this->pkcs5Unpad( $str );
        return $str;
    }

    //bin2hex还原
    private function hex2bin($hexData)
    {
        $binData = "";
        for($i = 0; $i < strlen ( $hexData ); $i += 2)
        {
            $binData .= chr(hexdec(substr($hexData, $i, 2)));
        }
        return $binData;
    }

    //PKCS5Padding
    private function pkcs5Pad($text, $blocksize)
    {
        $pad = $blocksize - (strlen ( $text ) % $blocksize);
        return $text . str_repeat ( chr ( $pad ), $pad );
    }

    private function pkcs5Unpad($text)
    {
        $pad = ord ( $text {strlen ( $text ) - 1} );
        if ($pad > strlen ( $text ))
            return false;
        if (strspn ( $text, chr ( $pad ), strlen ( $text ) - $pad ) != $pad)
            return false;
        return substr ( $text, 0, - 1 * $pad );
    }

}

?>