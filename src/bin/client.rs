extern crate cita_tool;
extern crate rand;
extern crate rustc_hex;
extern crate zktx;

use cita_tool::client::basic::Client;
use cita_tool::client::basic::ClientExt;
use cita_tool::client::TransactionOptions;
use cita_tool::crypto::{Encryption, KeyPair};
use cita_tool::remove_0x;
use cita_tool::rpctypes::{ParamsValue, ResponseValue};
use rand::{thread_rng, Rng};
use rustc_hex::{FromHex, ToHex};
use std::thread::sleep;
use std::time::Duration;
use zktx::base::*;
use zktx::c2p::*;
use zktx::contract::*;
use zktx::p2c::*;

struct Account {
    pub balance: String, //in homomorphic encrpytion, = vP1+rP2
    pub address: String, //address
    v: [u64; 2],         //private information: balance
    r: [u64; 4],         //private information: random number
    sk: String,          //private information: secret_key
}

struct PrivateSendMessage {
    v: [u64; 2],
    r: [u64; 2],
}

struct PrivateReceiveMessage {
    v: [u64; 2],
    r: [u64; 2],
}

impl Account {
    pub fn new(v: [u64; 2], r: [u64; 2]) -> Self {
        let rng = &mut thread_rng();
        let sk = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let address = address(sk.clone());
        let balance = v_p1_add_r_p2(v, r);
        Account {
            balance,
            address,
            v,
            r: [r[0], r[1], 0, 0],
            sk,
        }
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }

    pub fn get_balance(&self) -> String {
        self.balance.clone()
    }

    fn add_balance(&mut self, value: String) {
        self.balance = ecc_add(self.balance.clone(), value);
    }

    fn sub_balance(&mut self, value: String) {
        self.balance = ecc_sub(self.balance.clone(), value);
    }

    pub fn send(
        &self,
        v: [u64; 2],
        rcm: [u64; 2],
        address: &str,
        block_number: u64,
    ) -> (SenderProof, PrivateSendMessage) {
        let rng = &mut thread_rng();
        let enc_random = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
        let (proof, hb, coin, delt_ba, enc) = p2c_info(
            self.r,
            rcm,
            self.v,
            v,
            address.to_string(),
            self.sk.clone(),
            enc_random,
        )
        .unwrap();
        assert_eq!(hb, self.get_balance());
        let enc1 = encrypt(
            [rcm[0], rcm[1], v[0], v[1]],
            enc_random,
            address.to_string(),
        );
        assert_eq!(enc, enc1);
        (
            SenderProof {
                proof,
                coin,
                delt_ba,
                enc,
                block_number,
            },
            PrivateSendMessage { v, r: rcm },
        )
    }

    pub fn send_refresh(&mut self, private_message: &PrivateSendMessage) {
        let pr = private_message.r;
        self.r = u644sub(self.r, [pr[0], pr[1], 0, 0]);
        let pv = private_message.v;
        let sv = self.v;
        let temp = u644sub([sv[0], sv[1], 0, 0], [pv[0], pv[1], 0, 0]);
        self.v = [temp[0], temp[1]];
    }

    pub fn receive(
        &self,
        enc: String,
        authentication_path: Vec<String>,
        index: Vec<bool>,
    ) -> (ReceiverProof, PrivateReceiveMessage) {
        let (va, rcm) = decrypt(enc, self.sk.clone());
        let rng = &mut thread_rng();
        let rcm_new = [rng.gen(), rng.gen()];
        let (proof, nullifier, root, delt_ba) = c2p_info(
            rcm,
            rcm_new,
            va,
            self.sk.clone(),
            authentication_path,
            index,
        )
        .unwrap();
        (
            ReceiverProof {
                proof,
                nullifier,
                root,
                delt_ba,
            },
            PrivateReceiveMessage { v: va, r: rcm_new },
        )
    }

    pub fn receive_refresh(&mut self, private_message: &PrivateReceiveMessage) {
        let pr = private_message.r;
        self.r = u644add(self.r, [pr[0], pr[1], 0, 0]);
        let pv = private_message.v;
        let sv = self.v;
        let temp = u644add([sv[0], sv[1], 0, 0], [pv[0], pv[1], 0, 0]);
        self.v = [temp[0], temp[1]];
    }

    pub fn check_coin(&self, coin: String, enc: String) -> bool {
        check(coin, enc, self.sk.clone())
    }

    pub fn state_out(&self, name: &str) {
        println!("{}: v = {:?}, r = {:?}", name, self.v, self.r);
    }
}

/*fn verify_send(message:&mut SendMessage,sender:&mut Account){
    assert!(p2c_verify(sender.get_balance(),message.coin,message.delt_ba,message.rp,message.enc,message.proof).unwrap());
    message.on_chain();
    sender.sub_balance(message.delt_ba);
}*/

/*fn verify_receive(message:&mut ReceiveMessage,receiver:&mut Account){
    assert!(c2p_verify(message.nullifier,message.root,message.delt_ba,message.proof).unwrap());
    message.on_chain();
    receiver.add_balance(message.delt_ba);
}*/

fn get_block_number(client: &Client) -> u64 {
    let height = client.get_current_height().map(|height| {
        println!("height: {:?}", height);
        height
    });

    height.unwrap()
}

fn set_balance(client: &mut Client, addr: &str, balance: &str) {
    let hasher = "05e3cb61";
    let mut data = hasher.to_string();
    data.push_str(&addr.as_bytes().to_hex());
    data.push_str(&balance.as_bytes().to_hex());
    println!("data={}", data);
    let tx = TransactionOptions::new()
        .set_address("0xffffffffffffffffffffffffffffffffff030001")
        .set_code(&data)
        .set_quota(Some(100_000));
    client.send_raw_transaction(tx).unwrap();
}

fn send_verify(client: &mut Client, addr: &str, proof: &SenderProof) {
    let hasher = "c73b5a8f";
    let mut data = hasher.to_string();
    data.push_str(&addr.as_bytes().to_hex());
    data.push_str(&proof.proof.as_bytes().to_hex());
    data.push_str(&proof.coin.as_bytes().to_hex());
    data.push_str(&proof.delt_ba.as_bytes().to_hex());
    data.push_str(&proof.enc.as_bytes().to_hex());
    println!("data={}", data);
    let tx = TransactionOptions::new()
        .set_address("0xffffffffffffffffffffffffffffffffff030001")
        .set_code(&data)
        .set_quota(Some(11_000_000));
    client.send_raw_transaction(tx).unwrap();
}

fn receive_verify(client: &mut Client, addr: &str, proof: &ReceiverProof) {
    let hasher = "882b30d2";
    let mut data = hasher.to_string();
    data.push_str(&addr.as_bytes().to_hex());
    data.push_str(&proof.proof.as_bytes().to_hex());
    data.push_str(&proof.nullifier.as_bytes().to_hex());
    data.push_str(&proof.root.as_bytes().to_hex());
    data.push_str(&proof.delt_ba.as_bytes().to_hex());
    println!("data={}", data);
    let tx = TransactionOptions::new()
        .set_address("0xffffffffffffffffffffffffffffffffff030001")
        .set_code(&data)
        .set_quota(Some(11_000_000));
    client.send_raw_transaction(tx).unwrap();
}

fn round_test() {
    let mut client = Client::new().set_uri("http://localhost:1337");

    //study create sendtransaction param
    let keypair = KeyPair::new(Encryption::Secp256k1);

    println!("addr = {:?}", keypair.address());

    client.set_private_key(&keypair.privkey());

    let rng = &mut thread_rng();
    let mut alice = Account::new([1001, 0], [rng.gen(), rng.gen()]);
    let mut bob = Account::new([1000, 0], [rng.gen(), rng.gen()]);

    //privacy_contract.set_banlance(alice.get_address(), alice.get_balance());
    let addr = alice.get_address();
    let balance = alice.get_balance();
    set_balance(&mut client, &addr, &balance);
    println!("alice set_balance, waiting ...");
    sleep(Duration::new(10, 0));
    //privacy_contract.set_banlance(bob.get_address(), bob.get_balance());
    let addr = bob.get_address();
    let balance = bob.get_balance();
    set_balance(&mut client, &addr, &balance);
    println!("bob set_balance, waiting ...");
    sleep(Duration::new(10, 0));

    // get current block number by jsonrpc
    let current_block_number = get_block_number(&client);
    let (alice_send_message, alice_private_send_message) = alice.send(
        [10, 0],
        [rng.gen(), rng.gen()],
        &bob.get_address(),
        current_block_number,
    );
    //verify_send(&mut alice_send_message,&mut alice);
    //    let (ok, path) = privacy_contract.send_verify(alice.get_address(), alice_send_message.clone());
    //    if !ok {
    //        panic!("alice send_verify failed");
    //    }
    send_verify(&mut client, &alice.get_address(), &alice_send_message);
    println!("alice send_verify, wait for log ...");
    //get path from log
    let log_data;
    loop {
        sleep(Duration::new(3, 0));
        let ret = client.get_logs(
            Some(vec![
                "0xc73b5a8f31a1a078a14123cc93687f4a59389c76caf88d5d2154d3f3ce25ff49",
            ]),
            Some(vec!["0xffffffffffffffffffffffffffffffffff030001"]),
            Some(&current_block_number.to_string()),
            None,
        );
        if ret.is_err() {
            println!("get log error {:?}", ret);
            continue;
        }
        let result = ret.unwrap().result();

        println!("result {:?}", result);

        if let Some(ResponseValue::Singe(ParamsValue::List(logs))) = result {
            if logs.is_empty() {
                continue;
            }
            let log = &logs[0];
            match log {
                ParamsValue::Map(m) => {
                    if let Some(ParamsValue::String(log_data_str)) = m.get("data").to_owned() {
                        log_data = remove_0x(&log_data_str).from_hex().unwrap();
                        break;
                    }
                }
                _ => continue,
            }
        }
    }

    let coin = String::from_utf8(log_data[0..64].to_vec()).unwrap();
    println!("coin in log {}", coin);
    let enc = String::from_utf8(log_data[64..64 + 192].to_vec()).unwrap();
    println!("enc in log {}", enc);
    let mut authentication_path = Vec::new();
    for i in 0..TREEDEPTH {
        let hash = String::from_utf8(log_data[64 + 192 + i * 64..64 + 192 + i * 64 + 64].to_vec())
            .unwrap();
        println!("authentication_path {} {}", i, hash);
        authentication_path.push(hash);
    }
    let mut index = Vec::new();
    for i in 0..TREEDEPTH {
        if log_data[64 + 192 + TREEDEPTH * 64 + i] == 1 {
            index.push(true);
        } else {
            index.push(false);
        }
    }
    println!("index in log {:?}", index);

    // use log confirm sender proof verified
    alice.send_refresh(&alice_private_send_message);
    alice.sub_balance(alice_send_message.delt_ba.clone());
    alice.state_out("alice");

    // bob get alice_send_message by private channel
    // or listen all message from privacy contract (Maybe filter by sender)
    // check is the coin is to bob?
    if bob.check_coin(coin.clone(), enc.clone()) {
        println!("There is a coin to me");
        let (bob_receive_message, bob_private_receive_message) =
            bob.receive(enc, authentication_path, index);
        //verify_receive(&mut bob_receive_message,&mut bob);
        //        if !privacy_contract.receive_verify(bob.get_address(), bob_receive_message.clone()) {
        //            panic!("bob receive_verify failed");
        //        }
        receive_verify(&mut client, &bob.get_address(), &bob_receive_message);
        bob.receive_refresh(&bob_private_receive_message);
        bob.add_balance(bob_receive_message.delt_ba);
        bob.state_out("bob");
    } else {
        println!("This coin is not mine");
    }

    println!("wait for a while ...");
    sleep(Duration::new(10, 0));

    let current_block_number = get_block_number(&client);
    let (bob_send_message, bob_private_send_message) = bob.send(
        [200, 0],
        [rng.gen(), rng.gen()],
        &alice.get_address(),
        current_block_number,
    );
    //verify_send(&mut bob_send_message,&mut bob);
    //    let (ok, path) = privacy_contract.send_verify(bob.get_address(), bob_send_message.clone());
    //    if !ok {
    //        panic!("bob send_verify failed");
    //    }
    send_verify(&mut client, &bob.get_address(), &bob_send_message);
    println!("bob send_verify, wait for log ...");
    //get path from log
    let log_data;
    loop {
        sleep(Duration::new(3, 0));
        let ret = client.get_logs(
            Some(vec![
                "0xc73b5a8f31a1a078a14123cc93687f4a59389c76caf88d5d2154d3f3ce25ff49",
            ]),
            Some(vec!["0xffffffffffffffffffffffffffffffffff030001"]),
            Some(&current_block_number.to_string()),
            None,
        );
        if ret.is_err() {
            println!("get log error {:?}", ret);
            continue;
        }
        let result = ret.unwrap().result();

        println!("result {:?}", result);

        if let Some(ResponseValue::Singe(ParamsValue::List(logs))) = result {
            if logs.is_empty() {
                continue;
            }
            let log = &logs[0];
            match log {
                ParamsValue::Map(m) => {
                    if let Some(ParamsValue::String(log_data_str)) = m.get("data").to_owned() {
                        log_data = remove_0x(&log_data_str).from_hex().unwrap();
                        break;
                    }
                }
                _ => continue,
            }
        }
    }

    let coin = String::from_utf8(log_data[0..64].to_vec()).unwrap();
    println!("coin in log {}", coin);
    let enc = String::from_utf8(log_data[64..64 + 192].to_vec()).unwrap();
    println!("enc in log {}", enc);
    let mut authentication_path = Vec::new();
    for i in 0..TREEDEPTH {
        let hash = String::from_utf8(log_data[64 + 192 + i * 64..64 + 192 + i * 64 + 64].to_vec())
            .unwrap();
        println!("authentication_path {} {}", i, hash);
        authentication_path.push(hash);
    }
    let mut index = Vec::new();
    for i in 0..TREEDEPTH {
        if log_data[64 + 192 + TREEDEPTH * 64 + i] == 1 {
            index.push(true);
        } else {
            index.push(false);
        }
    }
    println!("index in log {:?}", index);

    bob.send_refresh(&bob_private_send_message);
    bob.sub_balance(bob_send_message.delt_ba.clone());
    bob.state_out("bob");

    if alice.check_coin(coin.clone(), enc.clone()) {
        println!("There is a coin to me");
        let (alice_receive_message, alice_private_receive_message) =
            alice.receive(enc, authentication_path, index);
        //verify_receive(&mut alice_receive_message,&mut alice);
        //        if !privacy_contract.receive_verify(alice.get_address(), alice_receive_message.clone()) {
        //            panic!("alice receive_verify failed");
        //        }
        receive_verify(&mut client, &alice.get_address(), &alice_receive_message);
        alice.receive_refresh(&alice_private_receive_message);
        alice.state_out("alice");
    } else {
        println!("This coin is not mine");
    }
}

fn main() {
    zktx::set_param_path("PARAMS");
    println!("Round Test:");

    round_test();

    println!("Test End.");
}
