extern crate rand;
extern crate zktx;

use rand::{thread_rng, Rng};
use zktx::base::*;
use zktx::c2p::*;
use zktx::contract::*;
use zktx::incrementalmerkletree::*;
use zktx::p2c::*;
use zktx::pedersen::PedersenDigest;
use zktx::u6442str;

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
        self.address.to_string()
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
        message: SenderProof,
        path: MerklePath<PedersenDigest>,
    ) -> (ReceiverProof, PrivateReceiveMessage) {
        let (va, rcm) = decrypt(message.enc, self.sk.clone());
        let rng = &mut thread_rng();
        let rcm_new = [rng.gen(), rng.gen()];
        let (proof, nullifier, root, delt_ba) = c2p_info(
            rcm,
            rcm_new,
            va,
            self.sk.clone(),
            path.authentication_path
                .iter()
                .map(|p| u6442str(p.0))
                .collect(),
            path.index,
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

fn round_test() {
    let mut privacy_contract = PrivacyContract::new();
    let rng = &mut thread_rng();
    let mut alice = Account::new([1001, 0], [rng.gen(), rng.gen()]);
    let mut bob = Account::new([1000, 0], [rng.gen(), rng.gen()]);

    privacy_contract.set_banlance(alice.get_address(), alice.get_balance());
    privacy_contract.set_banlance(bob.get_address(), bob.get_balance());

    // get current block number by jsonrpc
    let mut current_block_number = 1 as u64;
    let (alice_send_message, alice_private_send_message) = alice.send(
        [10, 0],
        [rng.gen(), rng.gen()],
        &bob.get_address(),
        current_block_number,
    );
    //verify_send(&mut alice_send_message,&mut alice);
    let (ok, path) = privacy_contract.send_verify(alice.get_address(), alice_send_message.clone());
    if !ok {
        panic!("alice send_verify failed");
    }
    let path = path.unwrap();
    // use log confirm sender proof verified
    alice.send_refresh(&alice_private_send_message);
    alice.sub_balance(alice_send_message.delt_ba.clone());
    alice.state_out("alice");

    // bob get alice_send_message by private channel
    // or listen all message from privacy contract (Maybe filter by sender)
    // check is the coin is to bob?
    if bob.check_coin(
        alice_send_message.coin.clone(),
        alice_send_message.enc.clone(),
    ) {
        println!("There is a coin to me");
        let (bob_receive_message, bob_private_receive_message) =
            bob.receive(alice_send_message, path);
        //verify_receive(&mut bob_receive_message,&mut bob);
        if !privacy_contract.receive_verify(bob.get_address(), bob_receive_message.clone()) {
            panic!("bob receive_verify failed");
        }
        bob.receive_refresh(&bob_private_receive_message);
        bob.add_balance(bob_receive_message.delt_ba);
        bob.state_out("bob");
    } else {
        println!("This coin is not mine");
    }

    current_block_number += 1;
    let (bob_send_message, bob_private_send_message) = bob.send(
        [200, 0],
        [rng.gen(), rng.gen()],
        &alice.get_address(),
        current_block_number,
    );
    //verify_send(&mut bob_send_message,&mut bob);
    let (ok, path) = privacy_contract.send_verify(bob.get_address(), bob_send_message.clone());
    if !ok {
        panic!("bob send_verify failed");
    }
    bob.send_refresh(&bob_private_send_message);
    bob.sub_balance(bob_send_message.delt_ba.clone());
    bob.state_out("bob");

    if alice.check_coin(bob_send_message.coin.clone(), bob_send_message.enc.clone()) {
        println!("There is a coin to me");
        let (alice_receive_message, alice_private_receive_message) =
            alice.receive(bob_send_message, path.unwrap());
        //verify_receive(&mut alice_receive_message,&mut alice);
        if !privacy_contract.receive_verify(alice.get_address(), alice_receive_message.clone()) {
            panic!("alice receive_verify failed");
        }
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
