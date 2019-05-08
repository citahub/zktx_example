extern crate rand;
extern crate zktx;

use rand::{thread_rng, Rng};
use zktx::base::*;
use zktx::c2p::*;
use zktx::p2c::*;

struct Account {
    pub balance: String, //in homomorphic encrpytion, = vP1+rP2
    pub address: String, //address
    v: [u64; 2],         //private information: balance
    r: [u64; 4],         //private information: random number
    sk: String,          //private information: secret_key
}

struct SendMessage {
    proof: String,
    //hb:([u64;4],[u64;4]),
    coin: String,
    delt_ba: String,
    enc: String,
    onchain: bool,
}

struct PrivateSendMessage {
    v: [u64; 2],
    r: [u64; 2],
}

impl SendMessage {
    pub fn on_chain(&mut self) {
        self.onchain = true;
    }

    pub fn is_on_chain(&self) -> bool {
        self.onchain
    }
}

struct ReceiveMessage {
    proof: String,
    nullifier: String,
    root: String,
    delt_ba: String,
    onchain: bool,
}

impl ReceiveMessage {
    pub fn on_chain(&mut self) {
        self.onchain = true;
    }

    pub fn is_on_chain(&self) -> bool {
        self.onchain
    }
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
    ) -> (SendMessage, PrivateSendMessage) {
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
            SendMessage {
                proof,
                coin,
                delt_ba,
                enc,
                onchain: false,
            },
            PrivateSendMessage { v, r: rcm },
        )
    }

    pub fn send_refresh(&mut self, private_message: &PrivateSendMessage, message: &SendMessage) {
        if message.is_on_chain() {
            let pr = private_message.r;
            self.r = u644sub(self.r, [pr[0], pr[1], 0, 0]);
            let pv = private_message.v;
            let sv = self.v;
            let temp = u644sub([sv[0], sv[1], 0, 0], [pv[0], pv[1], 0, 0]);
            self.v = [temp[0], temp[1]];
        }
    }

    pub fn receive(&self, message: SendMessage) -> (ReceiveMessage, PrivateReceiveMessage) {
        let (va, rcm) = decrypt(message.enc, self.sk.clone());
        let rng = &mut thread_rng();
        let path: Vec<String> = (0..TREEDEPTH)
            .map(|_| {
                let mut v: [u64; 4] = [0; 4];
                for val in v.iter_mut() {
                    *val = rng.gen();
                }
                zktx::u6442str(v)
            })
            .collect();
        let locs: Vec<bool> = (0..TREEDEPTH).map(|_| rng.gen()).collect::<Vec<bool>>();
        let rcm_new = [rng.gen(), rng.gen()];
        let (proof, nullifier, root, delt_ba) =
            c2p_info(rcm, rcm_new, va, self.sk.clone(), path, locs).unwrap();
        (
            ReceiveMessage {
                proof,
                nullifier,
                root,
                delt_ba,
                onchain: false,
            },
            PrivateReceiveMessage { v: va, r: rcm_new },
        )
    }

    pub fn receive_refresh(
        &mut self,
        private_message: &PrivateReceiveMessage,
        message: &ReceiveMessage,
    ) {
        if message.is_on_chain() {
            let pr = private_message.r;
            self.r = u644add(self.r, [pr[0], pr[1], 0, 0]);
            let pv = private_message.v;
            let sv = self.v;
            let temp = u644add([sv[0], sv[1], 0, 0], [pv[0], pv[1], 0, 0]);
            self.v = [temp[0], temp[1]];
        }
    }

    pub fn check_coin(&self, coin: String, enc: String) -> bool {
        check(coin, enc, self.sk.clone())
    }

    pub fn state_out(&self, name: &str) {
        println!("{}: v = {:?}, r = {:?}", name, self.v, self.r);
    }
}

fn verify_send(message: &mut SendMessage, sender: &mut Account) {
    assert!(p2c_verify(
        sender.get_balance(),
        message.coin.clone(),
        message.delt_ba.clone(),
        message.enc.clone(),
        sender.address.clone(),
        message.proof.clone()
    )
    .unwrap());
    message.on_chain();
    sender.sub_balance(message.delt_ba.clone());
}

fn verify_receive(message: &mut ReceiveMessage, receiver: &mut Account) {
    assert!(c2p_verify(
        message.nullifier.clone(),
        message.root.clone(),
        message.delt_ba.clone(),
        message.proof.clone()
    )
    .unwrap());
    message.on_chain();
    receiver.add_balance(message.delt_ba.clone());
}

fn round_test() {
    let rng = &mut thread_rng();
    let mut alice = Account::new([1001, 0], [rng.gen(), rng.gen()]);
    let mut bob = Account::new([1000, 0], [rng.gen(), rng.gen()]);

    let (mut alice_send_message, alice_private_send_message) =
        alice.send([10, 0], [rng.gen(), rng.gen()], &bob.get_address());
    verify_send(&mut alice_send_message, &mut alice);
    alice.send_refresh(&alice_private_send_message, &alice_send_message);
    alice.state_out("alice");

    assert!(bob.check_coin(
        alice_send_message.coin.clone(),
        alice_send_message.enc.clone()
    ));
    let (mut bob_receive_message, bob_private_receive_message) = bob.receive(alice_send_message);
    verify_receive(&mut bob_receive_message, &mut bob);
    bob.receive_refresh(&bob_private_receive_message, &bob_receive_message);
    bob.state_out("bob");

    let (mut bob_send_message, bob_private_send_message) =
        bob.send([200, 0], [rng.gen(), rng.gen()], &alice.get_address());
    verify_send(&mut bob_send_message, &mut bob);
    bob.send_refresh(&bob_private_send_message, &bob_send_message);
    bob.state_out("bob");

    assert!(alice.check_coin(bob_send_message.coin.clone(), bob_send_message.enc.clone()));
    let (mut alice_receive_message, alice_private_receive_message) =
        alice.receive(bob_send_message);
    verify_receive(&mut alice_receive_message, &mut alice);
    alice.receive_refresh(&alice_private_receive_message, &alice_receive_message);
    alice.state_out("alice");
}

fn main() {
    zktx::set_param_path("PARAMS");
    println!("Round Test:");

    round_test();

    println!("Test End.");
}
