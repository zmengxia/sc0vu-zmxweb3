<?php

/**
 * This file is part of web3.php package.
 *
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 *
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3;

use ethtool\Callback;
use InvalidArgumentException;
use Web3\Eth;
use Web3\Providers\Provider;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\RequestManager;
use Web3\RequestManagers\HttpRequestManager;
use Web3\Utils;
use Web3\Contracts\Ethabi;
use Web3\Contracts\Types\Address;
use Web3\Contracts\Types\Boolean;
use Web3\Contracts\Types\Bytes;
use Web3\Contracts\Types\DynamicBytes;
use Web3\Contracts\Types\Integer;
use Web3\Contracts\Types\Str;
use Web3\Contracts\Types\Uinteger;
use Web3\Validators\AddressValidator;
use Web3\Validators\HexValidator;
use Web3\Formatters\AddressFormatter;
use Web3\Validators\StringValidator;
use kornrunner\Keccak;
use Elliptic\EC;
use xtype\Ethereum\RLP\RLP;

class Contract
{
    /**
     * provider
     *
     * @var \Web3\Providers\Provider
     */
    protected $provider;

    /**
     * abi
     *
     * @var array
     */
    protected $abi;

    /**
     * constructor
     *
     * @var array
     */
    protected $constructor = [];

    /**
     * functions
     *
     * @var array
     */
    protected $functions = [];

    /**
     * events
     *
     * @var array
     */
    protected $events = [];

    /**
     * toAddress
     *
     * @var string
     */
    protected $toAddress;

    /**
     * bytecode
     *
     * @var string
     */
    protected $bytecode;

    /**
     * eth
     *
     * @var \Web3\Eth
     */
    protected $eth;

    /**
     * ethabi
     *
     * @var \Web3\Contracts\Ethabi
     */
    protected $ethabi;

    /**
     * construct
     *
     * @param string|\Web3\Providers\Provider $provider
     * @param string|\stdClass|array $abi
     * @return void
     */
    public function __construct($provider, $abi)
    {
        if (is_string($provider) && (filter_var($provider, FILTER_VALIDATE_URL) !== false)) {
            // check the uri schema
            if (preg_match('/^https?:\/\//', $provider) === 1) {
                $requestManager = new HttpRequestManager($provider);

                $this->provider = new HttpProvider($requestManager);
            }
        } else if ($provider instanceof Provider) {
            $this->provider = $provider;
        }
        //$abi = Utils::jsonToArray($abi, 5);
        $abi = json_decode($abi,true);
        foreach ($abi as $item) {
            if (isset($item['type'])) {
                if ($item['type'] === 'function') {
                    $this->functions[$item['name']] = $item;
                } elseif ($item['type'] === 'constructor') {
                    $this->constructor = $item;
                } elseif ($item['type'] === 'event') {
                    $this->events[$item['name']] = $item;
                }
            }
        }
        $this->abi = $abi;
        $this->eth = new Eth($this->provider);
        $this->ethabi = new Ethabi([
            'address' => new Address,
            'bool' => new Boolean,
            'bytes' => new Bytes,
            'dynamicBytes' => new DynamicBytes,
            'int' => new Integer,
            'string' => new Str,
            'uint' => new Uinteger,
        ]);
    }

    /**
     * call
     *
     * @param string $name
     * @param array $arguments
     * @return void
     */
    // public function __call($name, $arguments)
    // {
    //     if (empty($this->provider)) {
    //         throw new \RuntimeException('Please set provider first.');
    //     }
    //     $class = explode('\\', get_class());
    //     if (preg_match('/^[a-zA-Z0-9]+$/', $name) === 1) {
    //     }
    // }

    /**
     * get
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        $method = 'get' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], []);
        }
        return false;
    }

    /**
     * set
     *
     * @param string $name
     * @param mixed $value
     * @return mixed
     */
    public function __set($name, $value)
    {
        $method = 'set' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], [$value]);
        }
        return false;
    }

    /**
     * getProvider
     *
     * @return \Web3\Providers\Provider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * setProvider
     *
     * @param \Web3\Providers\Provider $provider
     * @return $this
     */
    public function setProvider($provider)
    {
        if ($provider instanceof Provider) {
            $this->provider = $provider;
        }
        return $this;
    }

    /**
     * getFunctions
     *
     * @return array
     */
    public function getFunctions()
    {
        return $this->functions;
    }

    /**
     * getEvents
     *
     * @return array
     */
    public function getEvents()
    {
        return $this->events;
    }

    /**
     * @return string
     */
    public function getToAddress()
    {
        return $this->toAddress;
    }

    /**
     * getConstructor
     *
     * @return array
     */
    public function getConstructor()
    {
        return $this->constructor;
    }

    /**
     * getAbi
     *
     * @return array
     */
    public function getAbi()
    {
        return $this->abi;
    }

    /**
     * setAbi
     *
     * @param string $abi
     * @return $this
     */
    public function setAbi($abi)
    {
        return $this->abi($abi);
    }

    /**
     * getEthabi
     *
     * @return array
     */
    public function getEthabi()
    {
        return $this->ethabi;
    }

    /**
     * getEth
     *
     * @return \Web3\Eth
     */
    public function getEth()
    {
        return $this->eth;
    }

    /**
     * setBytecode
     *
     * @param string $bytecode
     * @return $this
     */
    public function setBytecode($bytecode)
    {
        return $this->bytecode($bytecode);
    }

    /**
     * setToAddress
     *
     * @param string $bytecode
     * @return $this
     */
    public function setToAddress($address)
    {
        return $this->at($address);
    }

    /**
     * at
     *
     * @param string $address
     * @return $this
     */
    public function at($address)
    {
        if (AddressValidator::validate($address) === false) {
            throw new InvalidArgumentException('Please make sure address is valid.');
        }
        $this->toAddress = AddressFormatter::format($address);

        return $this;
    }

    /**
     * bytecode
     *
     * @param string $bytecode
     * @return $this
     */
    public function bytecode($bytecode)
    {
        if (HexValidator::validate($bytecode) === false) {
            throw new InvalidArgumentException('Please make sure bytecode is valid.');
        }
        $this->bytecode = Utils::stripZero($bytecode);

        return $this;
    }

    /**
     * abi
     *
     * @param string $abi
     * @return $this
     */
    public function abi($abi)
    {
        if (StringValidator::validate($abi) === false) {
            throw new InvalidArgumentException('Please make sure abi is valid.');
        }
        $abi = Utils::jsonToArray($abi, 5);

        foreach ($abi as $item) {
            if (isset($item['type'])) {
                if ($item['type'] === 'function') {
                    $this->functions[$item['name']] = $item;
                } elseif ($item['type'] === 'constructor') {
                    $this->constructor = $item;
                } elseif ($item['type'] === 'event') {
                    $this->events[$item['name']] = $item;
                }
            }
        }
        $this->abi = $abi;

        return $this;
    }

    /**
     * new
     * Deploy a contruct with params.
     *
     * @param mixed
     * @return void
     */
    public function new()
    {
        if (isset($this->constructor)) {
            $constructor = $this->constructor;
            $arguments = func_get_args();
            $callback = array_pop($arguments);

            if (count($arguments) < count($constructor['inputs'])) {
                throw new InvalidArgumentException('Please make sure you have put all constructor params and callback.');
            }
            if (is_callable($callback) !== true) {
                throw new \InvalidArgumentException('The last param must be callback function.');
            }
            if (!isset($this->bytecode)) {
                throw new \InvalidArgumentException('Please call bytecode($bytecode) before new().');
            }
            $params = array_splice($arguments, 0, count($constructor['inputs']));
            $data = $this->ethabi->encodeParameters($constructor, $params);
            $transaction = [];

            if (count($arguments) > 0) {
                $transaction = $arguments[0];
            }
            $transaction['data'] = '0x' . $this->bytecode . Utils::stripZero($data);

            $this->eth->sendTransaction($transaction, function ($err, $transaction) use ($callback){
                if ($err !== null) {
                    return call_user_func($callback, $err, null);
                }
                return call_user_func($callback, null, $transaction);
            });
        }
    }

    /**
     * send
     * Send function method.
     *
     * @param mixed
     * @return void
     */
    public function send()
    {
        if (isset($this->functions)) {
            $arguments = func_get_args();
            $method = array_splice($arguments, 0, 1)[0];
            $callback = array_pop($arguments);

            if (!is_string($method) || !isset($this->functions[$method])) {
                throw new InvalidArgumentException('Please make sure the method exists.');
            }
            $function = $this->functions[$method];

            if (count($arguments) < count($function['inputs'])) {
                throw new InvalidArgumentException('Please make sure you have put all function params and callback.');
            }
            if (is_callable($callback) !== true) {
                throw new \InvalidArgumentException('The last param must be callback function.');
            }
            $params = array_splice($arguments, 0, count($function['inputs']));
            $data = $this->ethabi->encodeParameters($function, $params);
            $functionName = Utils::jsonMethodToString($function);
            $functionSignature = $this->ethabi->encodeFunctionSignature($functionName);
            $transaction = [];
            if (count($arguments) > 0) {
                $transaction = $arguments[0];
            }
            $key  = $transaction['key'];
            unset($transaction['key']);
            //从服务器获取gas
            $cc = new Callback();
            $this->eth->estimateGas($transaction,$cc);
            $transaction['gas'] = dechex(json_decode($cc->result,true)*5);
            //获取用户地址
            $addr = $transaction['from'];
            unset($transaction['from']);
            $chainId = 0;
            //获取对方地址
            $transaction['to'] = $this->toAddress;
            //data   必传
            $transaction['data'] = $functionSignature . Utils::stripZero($data);
            //获取 gasprice
            $ca = new Callback();
            $this->eth->gasPrice($ca);
            $transaction['gasPrice'] = dechex(json_decode($ca->result,true));
            //获取 nonce
            $cd = new Callback();
            $this->eth->getTransactionCount($addr, 'pending',$cd);
            $transaction['nonce'] = dechex(json_decode($cd->result,true));

            // 合并数据
            $transaction = array_merge([
                'nonce' => '01',
                'gasPrice' => '',
                'gas' => '',
                'to' => '',
                'value' => '',
                'data' => '',
            ], $transaction);
            if ($chainId >0){
                $transaction['v'] = dechex($chainId);
                $transaction['r'] = '';
                $transaction['s'] = '';
            }

            $raw = $this->rawEncode($transaction);
            //签名
            $signature = $this->sign($addr, $raw,$key);
            // 按照这个顺序，不然序列会错误
            $transaction['v'] = dechex($signature->recoveryParam + 27 + ($chainId ? $chainId * 2 + 8 : 0));
            $transaction['r'] = $signature->r->toString('hex');
            $transaction['s'] = $signature->s->toString('hex');
            // 签署的RAW
            $signRaw = $this->rawEncode($transaction);
            // 发送交易
            //return $this->eth->sendRawTransaction(\xtype\Ethereum\Utils::add0x($signRaw));
            //print_r($transaction);die;
            $this->eth->sendRawTransaction(\xtype\Ethereum\Utils::add0x($signRaw), function ($err, $transaction) use ($callback){
                if ($err !== null) {
                    return call_user_func($callback, $err, null);
                }
                return call_user_func($callback, null, $transaction);
            });
        }
    }

    /**
     * 对交易数据进行签名
     * @param $pri 十六进制私钥
     * @param $msg 十六进制数据
     * @return $signature
     */
    public function sign($addr, $data,$key)
    {
        // 得到私钥
        $prikey = $key;
        // sha1
        $hash = Keccak::hash(hex2bin($data), 256);

        $ec = new EC('secp256k1');
        // Generate keys
        $key = $ec->keyFromPrivate($prikey);
        // Sign message (can be hex sequence or array)
        $signature = $key->sign($hash, ['canonical' => true]);

        // Verify signature
        return $signature;
    }

    /**
     * RLPencode
     */
    public function rawEncode(array $input): string
    {
        $rlp  = new RLP();
        $data = [];
        foreach ($input as $item) {
            // 如果值是无效值：0、0x0，将其列为空串
            $data[] = $item && hexdec(\xtype\Ethereum\Utils::remove0x($item)) != 0 ? \xtype\Ethereum\Utils::add0x($item) : '';
        }
        return $rlp->encode($data)->toString('hex');
    }

    /**
     * 获取ChainId
     */
    public function getChainId()
    {
        return 0;
        if ($this->chainId === null) {
            $this->chainId = $this->net_version();
        }
        return $this->chainId;
    }

    /**
     * call
     * Call function method.
     *
     * @param mixed
     * @return void
     */
    public function call()
    {
        if (isset($this->functions)) {
            $arguments = func_get_args();
            $method = array_splice($arguments, 0, 1)[0];
            $callback = array_pop($arguments);

            if (!is_string($method) || !isset($this->functions[$method])) {
                throw new InvalidArgumentException('Please make sure the method exists.');
            }
            $function = $this->functions[$method];

            if (count($arguments) < count($function['inputs'])) {
                throw new InvalidArgumentException('Please make sure you have put all function params and callback.');
            }
            if (is_callable($callback) !== true) {
                throw new \InvalidArgumentException('The last param must be callback function.');
            }
            $params = array_splice($arguments, 0, count($function['inputs']));
            $data = $this->ethabi->encodeParameters($function, $params);
            $functionName = Utils::jsonMethodToString($function);
            $functionSignature = $this->ethabi->encodeFunctionSignature($functionName);
            $transaction = [];

            if (count($arguments) > 0) {
                $transaction = $arguments[0];
            }
            $transaction['to'] = $this->toAddress;
            $transaction['data'] = $functionSignature . Utils::stripZero($data);

            $this->eth->call($transaction, function ($err, $transaction) use ($callback, $function){
                if ($err !== null) {
                    return call_user_func($callback, $err, null);
                }
                $decodedTransaction = $this->ethabi->decodeParameters($function, $transaction);

                return call_user_func($callback, null, $decodedTransaction);
            });
        }
    }
    public function array_to_object($arr) {
        if (gettype($arr) != 'array') {
            return;
        }
        foreach ($arr as $k => $v) {
            if (gettype($v) == 'array' || getType($v) == 'object') {
                $arr[$k] = (object)array_to_object($v);
            }
        }

        return (object)$arr;
    }
    /**
     * estimateGas
     * Estimate function gas.
     *
     * @param mixed
     * @return void
     */
    public function estimateGas()
    {
        if (isset($this->functions) || isset($this->constructor)) {
            $arguments = func_get_args();
            $callback = array_pop($arguments);

            if (empty($this->toAddress) && !empty($this->bytecode)) {
                $constructor = $this->constructor;

                if (count($arguments) < count($constructor['inputs'])) {
                    throw new InvalidArgumentException('Please make sure you have put all constructor params and callback.');
                }
                if (is_callable($callback) !== true) {
                    throw new \InvalidArgumentException('The last param must be callback function.');
                }
                if (!isset($this->bytecode)) {
                    throw new \InvalidArgumentException('Please call bytecode($bytecode) before estimateGas().');
                }
                $params = array_splice($arguments, 0, count($constructor['inputs']));
                $data = $this->ethabi->encodeParameters($constructor, $params);
                $transaction = [];

                if (count($arguments) > 0) {
                    $transaction = $arguments[0];
                }
                $transaction['to'] = '';
                $transaction['data'] = '0x' . $this->bytecode . Utils::stripZero($data);
            } else {
                $method = array_splice($arguments, 0, 1)[0];

                if (!is_string($method) && !isset($this->functions[$method])) {
                    throw new InvalidArgumentException('Please make sure the method is existed.');
                }
                $function = $this->functions[$method];

                if (count($arguments) < count($function['inputs'])) {
                    throw new InvalidArgumentException('Please make sure you have put all function params and callback.');
                }
                if (is_callable($callback) !== true) {
                    throw new \InvalidArgumentException('The last param must be callback function.');
                }
                $params = array_splice($arguments, 0, count($function['inputs']));
                $data = $this->ethabi->encodeParameters($function, $params);
                $functionName = Utils::jsonMethodToString($function);
                $functionSignature = $this->ethabi->encodeFunctionSignature($functionName);
                $transaction = [];

                if (count($arguments) > 0) {
                    $transaction = $arguments[0];
                }
                $transaction['to'] = $this->toAddress;
                $transaction['data'] = $functionSignature . Utils::stripZero($data);
            }

            $this->eth->estimateGas($transaction, function ($err, $gas) use ($callback){
                if ($err !== null) {
                    return call_user_func($callback, $err, null);
                }
                return call_user_func($callback, null, $gas);
            });
        }
    }

    /**
     * getData
     * Get the function method call data.
     * With this function, you can send signed contract function transaction.
     * 1. Get the funtion data with params.
     * 2. Sign the data with user private key.
     * 3. Call sendRawTransaction.
     *
     * @param mixed
     * @return void
     */
    public function getData()
    {
        if (isset($this->functions) || isset($this->constructor)) {
            $arguments = func_get_args();
            $functionData = '';

            if (empty($this->toAddress) && !empty($this->bytecode)) {
                $constructor = $this->constructor;

                if (count($arguments) < count($constructor['inputs'])) {
                    throw new InvalidArgumentException('Please make sure you have put all constructor params and callback.');
                }
                if (!isset($this->bytecode)) {
                    throw new \InvalidArgumentException('Please call bytecode($bytecode) before getData().');
                }
                $params = array_splice($arguments, 0, count($constructor['inputs']));
                $data = $this->ethabi->encodeParameters($constructor, $params);
                $functionData = $this->bytecode . Utils::stripZero($data);
            } else {
                $method = array_splice($arguments, 0, 1)[0];

                if (!is_string($method) && !isset($this->functions[$method])) {
                    throw new InvalidArgumentException('Please make sure the method is existed.');
                }
                $function = $this->functions[$method];

                if (count($arguments) < count($function['inputs'])) {
                    throw new InvalidArgumentException('Please make sure you have put all function params and callback.');
                }
                $params = array_splice($arguments, 0, count($function['inputs']));
                $data = $this->ethabi->encodeParameters($function, $params);
                $functionName = Utils::jsonMethodToString($function);
                $functionSignature = $this->ethabi->encodeFunctionSignature($functionName);
                $functionData = Utils::stripZero($functionSignature) . Utils::stripZero($data);
            }
            return $functionData;
        }
    }
}
