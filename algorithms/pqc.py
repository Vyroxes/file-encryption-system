from pqcrypto.kem import (
    ml_kem_512,
    ml_kem_768,
    ml_kem_1024,
)
from pqcrypto.sign import (
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_256f,
    slh_dsa_sha2_256s,
    slh_dsa_shake_128f,
    slh_dsa_shake_128s,
    slh_dsa_shake_192f,
    slh_dsa_shake_192s,
    slh_dsa_shake_256f,
    slh_dsa_shake_256s,
)


ML_KEM_MODULES = {
    "ML-KEM-1024": ml_kem_1024,
    "ML-KEM-768": ml_kem_768,
    "ML-KEM-512": ml_kem_512,
}

ML_DSA_MODULES = {
    "ML-DSA-87": ml_dsa_87,
    "ML-DSA-65": ml_dsa_65,
    "ML-DSA-44": ml_dsa_44,
}

SLH_DSA_MODULES = {
    "SLH-DSA-SHAKE-256s": slh_dsa_shake_256s,
    "SLH-DSA-SHAKE-256f": slh_dsa_shake_256f,
    "SLH-DSA-SHA2-256s": slh_dsa_sha2_256s,
    "SLH-DSA-SHA2-256f": slh_dsa_sha2_256f,
    "SLH-DSA-SHAKE-192s": slh_dsa_shake_192s,
    "SLH-DSA-SHAKE-192f": slh_dsa_shake_192f,
    "SLH-DSA-SHA2-192s": slh_dsa_sha2_192s,
    "SLH-DSA-SHA2-192f": slh_dsa_sha2_192f,
    "SLH-DSA-SHAKE-128s": slh_dsa_shake_128s,
    "SLH-DSA-SHAKE-128f": slh_dsa_shake_128f,
    "SLH-DSA-SHA2-128s": slh_dsa_sha2_128s,
    "SLH-DSA-SHA2-128f": slh_dsa_sha2_128f,
}