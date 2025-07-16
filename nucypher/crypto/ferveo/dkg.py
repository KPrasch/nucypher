from typing import List, Union

from nucypher_core.ferveo import (
    AggregatedTranscript,
    CiphertextHeader,
    DecryptionSharePrecomputed,
    DecryptionShareSimple,
    Dkg,
    DkgPublicKey,
    FerveoVariant,
    HandoverTranscript,
    Keypair,
    Transcript,
    Validator,
    ValidatorMessage,
)

from nucypher.utilities.logging import Logger

LOGGER = Logger('ferveo-dkg')


_VARIANTS = {
    FerveoVariant.Simple: AggregatedTranscript.create_decryption_share_simple,
    FerveoVariant.Precomputed: AggregatedTranscript.create_decryption_share_precomputed,
}


def _make_dkg(
    me: Validator,
    ritual_id: int,
    shares: int,
    threshold: int,
    nodes: List[Validator],
) -> Dkg:
    dkg = Dkg(
        tau=ritual_id,
        shares_num=shares,
        security_threshold=threshold,
        validators=nodes,
        me=me
    )
    LOGGER.debug(f"Initialized DKG backend for {threshold}/{shares} nodes: {', '.join(n.address[:6] for n in nodes)}")
    return dkg


def generate_transcript(*args, **kwargs) -> Transcript:
    dkg = _make_dkg(*args, **kwargs)
    transcript = dkg.generate_transcript()
    return transcript


def derive_public_key(*args, **kwargs) -> DkgPublicKey:
    dkg = _make_dkg(*args, **kwargs)
    return dkg.public_key


def aggregate_transcripts(
    validator_messages: List[ValidatorMessage], shares: int, *args, **kwargs
) -> AggregatedTranscript:
    validators = [vm.validator for vm in validator_messages]
    _dkg = _make_dkg(nodes=validators, shares=shares, *args, **kwargs)
    pvss_aggregated = _dkg.aggregate_transcripts(validator_messages)
    verify_aggregate(pvss_aggregated, shares, validator_messages)
    LOGGER.debug(
        f"derived final DKG key {bytes(pvss_aggregated.public_key).hex()[:10]}"
    )
    return pvss_aggregated


def verify_aggregate(
    pvss_aggregated: AggregatedTranscript,
    shares: int,
    transcripts: List[ValidatorMessage],
):
    pvss_aggregated.verify(shares, transcripts)


def produce_decryption_share(
    nodes: List[Validator],
    aggregated_transcript: AggregatedTranscript,
    keypair: Keypair,
    ciphertext_header: CiphertextHeader,
    aad: bytes,
    variant: FerveoVariant,
    *args, **kwargs
) -> Union[DecryptionShareSimple, DecryptionSharePrecomputed]:
    dkg = _make_dkg(nodes=nodes, *args, **kwargs)
    if not all((nodes, aggregated_transcript, keypair, ciphertext_header, aad)):
        raise Exception("missing arguments")  # sanity check
    try:
        derive_share = _VARIANTS[variant]
    except KeyError:
        raise ValueError(f"Invalid variant {variant}")
    share = derive_share(
        # first arg here is intended to be "self" since the method is unbound
        aggregated_transcript,
        dkg,
        ciphertext_header,
        aad,
        keypair
    )
    return share


def initiate_handover(
    nodes: List[Validator],
    aggregated_transcript: AggregatedTranscript,
    handover_slot_index: int,
    keypair: Keypair,
    *args,
    **kwargs,
) -> HandoverTranscript:
    if not all((nodes, aggregated_transcript, keypair)):
        raise Exception("missing arguments")  # sanity check

    dkg = _make_dkg(nodes=nodes, *args, **kwargs)
    handover_transcript = dkg.generate_handover_transcript(
        aggregated_transcript,
        handover_slot_index,
        keypair,
    )
    return handover_transcript


def finalize_handover(
    aggregated_transcript: AggregatedTranscript,
    handover_transcript: HandoverTranscript,
    keypair: Keypair,
) -> HandoverTranscript:
    if not all((aggregated_transcript, handover_transcript, keypair)):
        raise Exception("missing arguments")  # sanity check

    new_aggregate = aggregated_transcript.finalize_handover(
        handover_transcript, keypair
    )
    return new_aggregate
