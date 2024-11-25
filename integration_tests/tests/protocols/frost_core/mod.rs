pub(crate) mod dkg;
pub(crate) mod sign;

pub fn make_signing_message() -> Vec<u8> {
    let message = "this is the message that is sent out";
    message.as_bytes().to_vec()
}
