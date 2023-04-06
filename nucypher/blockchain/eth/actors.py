import json
from decimal import Decimal

import maya
import time
from constant_sorrow.constants import FULL
from eth_typing import ChecksumAddress
from ferveo_py import ExternalValidator
from hexbytes import HexBytes
from typing import Optional, Tuple, Union, List
from web3 import Web3
from web3.types import TxReceipt

from nucypher.acumen.nicknames import Nickname
from nucypher.blockchain.economics import Economics
from nucypher.blockchain.eth.agents import (
    AdjudicatorAgent,
    ContractAgency,
    CoordinatorAgent,
    NucypherTokenAgent,
    PREApplicationAgent,
)
from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.blockchain.eth.decorators import save_receipt, validate_checksum_address
from nucypher.blockchain.eth.deployers import (
    AdjudicatorDeployer,
    BaseContractDeployer,
    NucypherTokenDeployer,
    PREApplicationDeployer,
    SubscriptionManagerDeployer,
)
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.blockchain.eth.signers import Signer
from nucypher.blockchain.eth.token import NU
from nucypher.blockchain.eth.trackers.dkg import RitualTracker
from nucypher.blockchain.eth.trackers.pre import WorkTracker
from nucypher.config.constants import DEFAULT_CONFIG_ROOT
from nucypher.crypto.ferveo.dkg import (
    AggregatedTranscript,
    DecryptionShare,
    Transcript,
)
from nucypher.crypto.powers import CryptoPower, TransactingPower, RitualisticPower
from nucypher.network.trackers import OperatorBondedTracker
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.policy.payment import ContractPayment
from nucypher.utilities.emitters import StdoutEmitter
from nucypher.utilities.logging import Logger


class BaseActor:
    """
    Concrete base class for any actor that will interface with NuCypher's ethereum smart contracts.
    """

    class ActorError(Exception):
        pass

    @validate_checksum_address
    def __init__(self,
                 domain: Optional[str],
                 registry: BaseContractRegistry,
                 transacting_power: Optional[TransactingPower] = None,
                 checksum_address: Optional[ChecksumAddress] = None,
                 economics: Optional[Economics] = None):

        if not (bool(checksum_address) ^ bool(transacting_power)):
            error = f'Pass transacting power or checksum address, got {checksum_address} and {transacting_power}.'
            raise ValueError(error)

        try:
            parent_address = self.checksum_address
            if checksum_address is not None:
                if parent_address != checksum_address:
                    raise ValueError(f"Can't have two different ethereum addresses. "
                                     f"Got {parent_address} and {checksum_address}.")
        except AttributeError:
            if transacting_power:
                self.checksum_address = transacting_power.account
            else:
                self.checksum_address = checksum_address

        self.economics = economics or Economics()
        self.transacting_power = transacting_power
        self.registry = registry
        self.network = domain
        self._saved_receipts = list()  # track receipts of transmitted transactions

    def __repr__(self):
        class_name = self.__class__.__name__
        r = "{}(address='{}')"
        r = r.format(class_name, self.checksum_address)
        return r

    def __eq__(self, other) -> bool:
        """Actors are equal if they have the same address."""
        try:
            return bool(self.checksum_address == other.checksum_address)
        except AttributeError:
            return False

    @property
    def eth_balance(self) -> Decimal:
        """Return this actor's current ETH balance"""
        blockchain = BlockchainInterfaceFactory.get_interface()  # TODO: EthAgent?  #1509
        balance = blockchain.client.get_balance(self.wallet_address)
        return Web3.from_wei(balance, 'ether')

    @property
    def wallet_address(self):
        return self.checksum_address


class NucypherTokenActor(BaseActor):
    """
    Actor to interface with the NuCypherToken contract
    """

    def __init__(self, registry: BaseContractRegistry, **kwargs):
        super().__init__(registry=registry, **kwargs)
        self.__token_agent = None

    @property
    def token_agent(self):
        if self.__token_agent:
            return self.__token_agent
        self.__token_agent = ContractAgency.get_agent(NucypherTokenAgent, registry=self.registry)
        return self.__token_agent

    @property
    def token_balance(self) -> NU:
        """Return this actor's current token balance"""
        balance = int(self.token_agent.get_balance(address=self.checksum_address))
        nu_balance = NU(balance, 'NuNit')
        return nu_balance


class ContractAdministrator(BaseActor):
    """
    The administrator of network contracts.
    """

    # Note: Deployer classes are sorted by deployment dependency order.

    standard_deployer_classes = (
        NucypherTokenDeployer,
        PREApplicationDeployer,
        SubscriptionManagerDeployer  # TODO: Move to dispatched/upgradeable section
    )

    dispatched_upgradeable_deployer_classes = (
        AdjudicatorDeployer,
    )

    upgradeable_deployer_classes = (
        *dispatched_upgradeable_deployer_classes,
    )

    aux_deployer_classes = (
        # Add more deployer classes here
    )

    # For ownership transfers.
    ownable_deployer_classes = (*dispatched_upgradeable_deployer_classes,)

    # Used in the automated deployment series.
    primary_deployer_classes = (*standard_deployer_classes,
                                *upgradeable_deployer_classes)

    # Comprehensive collection.
    all_deployer_classes = (*primary_deployer_classes,
                            *aux_deployer_classes,
                            *ownable_deployer_classes)

    class UnknownContract(ValueError):
        pass

    def __init__(self, *args, **kwargs):
        self.log = Logger("Deployment-Actor")
        self.deployers = {d.contract_name: d for d in self.all_deployer_classes}
        super().__init__(*args, **kwargs)

    def __repr__(self):
        r = '{name} - {deployer_address})'.format(name=self.__class__.__name__, deployer_address=self.checksum_address)
        return r

    def __get_deployer(self, contract_name: str):
        try:
            Deployer = self.deployers[contract_name]
        except KeyError:
            raise self.UnknownContract(contract_name)
        return Deployer

    def deploy_contract(self,
                        contract_name: str,
                        gas_limit: int = None,
                        deployment_mode=FULL,
                        ignore_deployed: bool = False,
                        progress=None,
                        confirmations: int = 0,
                        deployment_parameters: dict = None,
                        emitter=None,
                        *args, **kwargs,
                        ) -> Tuple[dict, BaseContractDeployer]:

        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')

        deployment_parameters = deployment_parameters or {}

        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry, economics=self.economics, *args, **kwargs)

        if Deployer._upgradeable:
            receipts = deployer.deploy(transacting_power=self.transacting_power,
                                       gas_limit=gas_limit,
                                       progress=progress,
                                       ignore_deployed=ignore_deployed,
                                       confirmations=confirmations,
                                       deployment_mode=deployment_mode,
                                       emitter=emitter,
                                       **deployment_parameters)
        else:
            receipts = deployer.deploy(transacting_power=self.transacting_power,
                                       gas_limit=gas_limit,
                                       progress=progress,
                                       confirmations=confirmations,
                                       deployment_mode=deployment_mode,
                                       ignore_deployed=ignore_deployed,
                                       emitter=emitter,
                                       **deployment_parameters)
        return receipts, deployer

    def upgrade_contract(self,
                         contract_name: str,
                         confirmations: int,
                         ignore_deployed: bool = False,
                         ) -> dict:
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        receipts = deployer.upgrade(transacting_power=self.transacting_power,
                                    ignore_deployed=ignore_deployed,
                                    confirmations=confirmations)
        return receipts

    def retarget_proxy(self,
                       confirmations: int,
                       contract_name: str,
                       target_address: str,
                       just_build_transaction: bool = False
                       ):
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        result = deployer.retarget(transacting_power=self.transacting_power,
                                   target_address=target_address,
                                   just_build_transaction=just_build_transaction,
                                   confirmations=confirmations)
        return result

    def rollback_contract(self, contract_name: str):
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        receipts = deployer.rollback(transacting_power=self.transacting_power)
        return receipts

    def save_deployment_receipts(self, receipts: dict, filename_prefix: str = 'deployment') -> str:
        config_root = DEFAULT_CONFIG_ROOT  # We force the use of the default here.
        filename = f'{filename_prefix}-receipts-{self.deployer_address[:6]}-{maya.now().epoch}.json'
        filepath = config_root / filename
        config_root.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as file:
            data = dict()
            for contract_name, contract_receipts in receipts.items():
                contract_records = dict()
                for tx_name, receipt in contract_receipts.items():
                    # Formatting
                    pretty_receipt = {item: str(result) for item, result in receipt.items()}
                    contract_records[tx_name] = pretty_receipt
                data[contract_name] = contract_records
            data = json.dumps(data, indent=4)
            file.write(data)
        return filepath


class Operator(BaseActor):

    READY_TIMEOUT = None  # (None or 0) == indefinite
    READY_POLL_RATE = 10

    class OperatorError(BaseActor.ActorError):
        pass

    def __init__(
        self,
        is_me: bool,
        eth_provider_uri: str,
        payment_method: ContractPayment,
        work_tracker: Optional[WorkTracker] = None,
        operator_address: Optional[ChecksumAddress] = None,
        signer: Signer = None,
        crypto_power: CryptoPower = None,
        client_password: str = None,
        transacting_power: TransactingPower = None,
        *args,
        **kwargs,
    ):

        # Falsy values may be passed down from the superclass
        if not eth_provider_uri:
            raise ValueError("ETH Provider URI is required to init a local character.")
        if not payment_method:
            raise ValueError("Payment method is required to init a local character.")

        if not transacting_power:
            transacting_power = TransactingPower(
                account=operator_address,
                password=client_password,
                signer=signer,
                cache=True,
            )

        # We pass the newly instantiated TransactingPower into consume_power_up here, even though it's accessible
        # on the instance itself (being composed in the __init__ of the base class, which we will call shortly)
        # because, given the need for initialization context, it's far less melodramatic
        # to do it here, and it's still available via the public crypto powers API.
        crypto_power.consume_power_up(transacting_power)

        self.payment_method = payment_method
        self._operator_bonded_tracker = OperatorBondedTracker(ursula=self)

        BaseActor.__init__(self, transacting_power=transacting_power, *args, **kwargs)

        self.log = Logger("worker")
        self.is_me = is_me
        self.__operator_address = operator_address
        self.__staking_provider_address = None  # set by block_until_ready
        if is_me:
            self.application_agent = ContractAgency.get_agent(PREApplicationAgent, registry=self.registry)
            self.work_tracker = work_tracker or WorkTracker(worker=self)

            # Multi-provider support
            # TODO: Abstract away payment provider
            eth_chain = self.application_agent.blockchain
            polygon_chain = payment_method.agent.blockchain

            # TODO: Verify consistency between network names and provider connection?
            # TODO: Allow bypassing of the enforcement above ^
            # TODO: Is chain ID stable and completely reliable?
            self.condition_providers = {
                eth_chain.client.chain_id: eth_chain.provider,
                polygon_chain.client.chain_id: polygon_chain.provider
            }

    def _local_operator_address(self):
        return self.__operator_address

    @property
    def wallet_address(self):
        return self.operator_address

    @property
    def staking_provider_address(self):
        if not self.__staking_provider_address:
            self.__staking_provider_address = self.get_staking_provider_address()
        return self.__staking_provider_address

    def get_staking_provider_address(self):
        self.__staking_provider_address = self.application_agent.get_staking_provider_from_operator(self.operator_address)
        self.checksum_address = self.__staking_provider_address
        self.nickname = Nickname.from_seed(self.checksum_address)
        return self.__staking_provider_address

    @property
    def is_confirmed(self):
        return self.application_agent.is_operator_confirmed(self.operator_address)

    def confirm_address(self, fire_and_forget: bool = True) -> Union[TxReceipt, HexBytes]:
        txhash_or_receipt = self.application_agent.confirm_operator_address(self.transacting_power, fire_and_forget=fire_and_forget)
        return txhash_or_receipt

    def block_until_ready(self, poll_rate: int = None, timeout: int = None):
        emitter = StdoutEmitter()
        client = self.application_agent.blockchain.client
        poll_rate = poll_rate or self.READY_POLL_RATE
        timeout = timeout or self.READY_TIMEOUT
        start, funded, bonded = maya.now(), False, False
        while not (funded and bonded):

            if timeout and ((maya.now() - start).total_seconds() > timeout):
                message = f"x Operator was not qualified after {timeout} seconds"
                emitter.message(message, color='red')
                raise self.ActorError(message)

            if not funded:
                # check for funds
                ether_balance = client.get_balance(self.operator_address)
                if ether_balance:
                    # funds found
                    funded, balance = True, Web3.from_wei(ether_balance, 'ether')
                    emitter.message(f"✓ Operator {self.operator_address} is funded with {balance} ETH", color='green')
                else:
                    emitter.message(f"! Operator {self.operator_address} is not funded with ETH", color="yellow")

            if (not bonded) and (self.get_staking_provider_address() != NULL_ADDRESS):
                bonded = True
                emitter.message(f"✓ Operator {self.operator_address} is bonded to staking provider {self.staking_provider_address}", color='green')
            else:
                emitter.message(f"! Operator {self.operator_address } is not bonded to a staking provider", color='yellow')

            time.sleep(poll_rate)

    def get_work_is_needed_check(self):
        def func(self):
            # we have not confirmed yet
            return not self.is_confirmed
        return func


class Ritualist(BaseActor):
    READY_TIMEOUT = None  # (None or 0) == indefinite
    READY_POLL_RATE = 10

    class RitualError(BaseActor.ActorError):
        """ritualist-specific errors"""

    def __init__(
            self,
            eth_provider_uri: str,
            crypto_power: CryptoPower,
            transacting_power: TransactingPower,
            *args,
            **kwargs,
    ):
        crypto_power.consume_power_up(transacting_power)
        super().__init__(transacting_power=transacting_power, *args, **kwargs)
        self.log = Logger("ritualist")
        self.coordinator_agent = ContractAgency.get_agent(
            CoordinatorAgent,
            registry=self.registry,
            eth_provider_uri=eth_provider_uri
        )
        self.ritual_tracker = RitualTracker(
            ritualist=self,
            eth_provider=self.coordinator_agent.blockchain.provider,
            contract=self.coordinator_agent.contract
        )

        self.dkg_storage = {
            "transcripts": {},
            "aggregated_transcripts": {},
            "public_keys": {},
            "generator_inverses": {},
        }
        self.ritual_power = crypto_power.power_ups(RitualisticPower)

    def get_ritual(self, ritual_id: int) -> CoordinatorAgent.Ritual:
        try:
            ritual = self.ritual_tracker.rituals[ritual_id]
        except KeyError:
            raise self.ActorError(f"{ritual_id} is not in the local cache")
        return ritual

    def store_transcript(self, ritual_id: int, transcript: Transcript) -> None:
        self.dkg_storage["transcripts"][ritual_id] = bytes(transcript)

    def store_aggregated_transcript(
        self, ritual_id: int, aggregated_transcript: AggregatedTranscript, public_key: bytes, generator_inverse
    ) -> None:
        self.dkg_storage["aggregated_transcripts"][ritual_id] = bytes(aggregated_transcript)
        self.dkg_storage["public_keys"][ritual_id] = public_key
        self.dkg_storage["generator_inverses"][ritual_id] = generator_inverse

    def get_aggregated_transcript(self, ritual_id: int) -> AggregatedTranscript:
        data = self.dkg_storage["aggregated_transcripts"][ritual_id]
        aggregated_transcript = AggregatedTranscript.from_bytes(data)
        return aggregated_transcript

    def get_transcript(self, ritual_id: int) -> AggregatedTranscript:
        data = self.dkg_storage["transcripts"][ritual_id]
        transcript = Transcript.from_bytes(data)
        return transcript

    def get_public_key(self, ritual_id: int) -> bytes:
        return self.dkg_storage["public_keys"][ritual_id]

    def recruit_validators(
            self,
            ritual: CoordinatorAgent.Ritual,
            timeout: int = 60
    ) -> List[Tuple[ExternalValidator, Transcript]]:

        validators = [n[0] for n in ritual.transcripts]
        if timeout > 0:
            nodes_to_discover = list(set(validators) - {self.checksum_address})
            self.block_until_specific_nodes_are_known(
                addresses=nodes_to_discover,
                timeout=timeout,
                allow_missing=0
            )

        result = list()
        for staking_provider_address, transcript_bytes in ritual.transcripts:
            if self.checksum_address == staking_provider_address:
                # Local
                external_validator = ExternalValidator(
                    address=self.checksum_address,
                    public_key=self.ritual_power.public_key()
                )
            else:
                # Remote
                try:
                    remote_ritualist = self.known_nodes[staking_provider_address]
                except KeyError:
                    raise self.ActorError(f"Unknown node {staking_provider_address}")
                public_key = remote_ritualist.public_keys(RitualisticPower)
                self.log.debug(f"Ferveo public key for {staking_provider_address} is {bytes(public_key).hex()[:-8:-1]}")
                external_validator = ExternalValidator(address=staking_provider_address, public_key=public_key)

            transcript = Transcript.from_bytes(transcript_bytes) if transcript_bytes else None
            result.append((external_validator, transcript))

        return result

    def perform_round_1(self, ritual_id: int, timestamp: int):
        ritual = self.get_ritual(ritual_id)
        status = self.coordinator_agent.get_ritual_status(ritual_id=ritual_id)
        if status != CoordinatorAgent.Ritual.Status.AWAITING_TRANSCRIPTS:
            raise self.ActorError(
                f"ritual #{ritual.id} is not waiting for transcripts."
            )
        node_index = self.coordinator_agent.get_node_index(
            ritual_id=ritual_id, node=self.checksum_address
        )
        if ritual.participants[node_index].transcript:
            raise self.RitualError(
                f"Node {self.transacting_power.account} has already posted a transcript for ritual {ritual_id}"
            )
        self.log.debug(
            f"performing round 1 of DKG ritual #{ritual_id} from blocktime {timestamp}"
        )

        nodes, transcripts = list(zip(*self.recruit_validators(ritual)))
        if any(transcripts):
            self.log.debug(f"ritual #{ritual_id} is in progress.  Using transcripts from other nodes.")
            self.ritual_tracker.refresh(fetch_rituals=[ritual_id])

        transcript = self.ritual_power.generate_transcript(
            nodes=nodes,
            threshold=(ritual.shares // 2) + 1,
            shares=ritual.shares,
            checksum_address=self.checksum_address,
            ritual_id=ritual_id
        )

        self.store_transcript(
            ritual_id=ritual_id,
            transcript=transcript,
        )

        receipt = self.coordinator_agent.post_transcript(
            node_index=self.coordinator_agent.get_node_index(
                ritual_id=ritual_id, node=self.checksum_address
            ),
            ritual_id=ritual_id,
            transcript=bytes(transcript),
            transacting_power=self.transacting_power,
        )

        total = ritual.total_transcripts + 1
        self.log.debug(f"{self.transacting_power.account[:8]} submitted a transcript for "
                       f"DKG ritual #{ritual_id} ({total}/{len(ritual.nodes)})")
        return receipt

    def perform_round_2(self, ritual_id: int, timestamp: int):
        ritual = self.get_ritual(ritual_id)
        status = self.coordinator_agent.get_ritual_status(ritual_id=ritual_id)
        if status != CoordinatorAgent.Ritual.Status.AWAITING_AGGREGATIONS:
            raise self.ActorError(
                f"ritual #{ritual.id} is not waiting for transcripts."
            )
        self.log.debug(
            f"{self.transacting_power.account[:8]} performing round 2 of DKG ritual #{ritual_id} from blocktime {timestamp}"
        )

        transcripts = self.recruit_validators(ritual)
        if not all([t for _, t in transcripts]):
            raise self.ActorError(
                f"ritual #{ritual_id} is missing transcripts from {len([t for t in transcripts if not t])} nodes."
            )

        aggregated_transcript, dkg_public_key, generator_inverse = self.ritual_power.aggregate_transcripts(
            threshold=(ritual.shares // 2) + 1,
            shares=ritual.shares,
            checksum_address=self.checksum_address,
            ritual_id=ritual_id,
            transcripts=transcripts
        )

        self.store_aggregated_transcript(
            ritual_id=ritual_id,
            aggregated_transcript=aggregated_transcript,
            public_key=dkg_public_key,
            generator_inverse=generator_inverse,
        )

        receipt = self.coordinator_agent.post_aggregation(
            ritual_id=ritual_id,
            node_index=self.coordinator_agent.get_node_index(
                ritual_id=ritual_id,
                node=self.checksum_address
            ),
            aggregated_transcript=aggregated_transcript,
            transacting_power=self.transacting_power
        )

        total = ritual.total_aggregations + 1
        self.log.debug(f"{self.transacting_power.account[:8]} aggregated a transcript for "
                       f"DKG ritual #{ritual_id} ({total}/{len(ritual.nodes)})")

        if total == len(ritual.nodes):
            self.log.debug(f"DKG ritual #{ritual_id} is ready to be finalized")
        return receipt

    def derive_decryption_share(
        self,
        ritual_id: int,
        ciphertext: bytes,
        conditions: ConditionLingo
    ) -> DecryptionShare:
        ritual = self.get_ritual(ritual_id)
        status = self.coordinator_agent.get_ritual_status(ritual_id=ritual_id)
        if status != CoordinatorAgent.Ritual.Status.FINALIZED:
            raise self.ActorError(f"ritual #{ritual.id} is not finalized.")

        nodes, transcripts = list(zip(*self.recruit_validators(ritual)))
        if not all(transcripts):
            raise self.ActorError(
                f"ritual #{ritual_id} is missing transcripts"
            )

        decryption_share = self.ritual_power.derive_decryption_share(
            nodes=nodes,
            threshold=(ritual.shares // 2) + 1,
            shares=ritual.shares,
            checksum_address=self.checksum_address,
            ritual_id=ritual_id,
            aggregated_transcript=self.get_aggregated_transcript(ritual_id),
            ciphertext=ciphertext,
            conditions=conditions
        )

        return decryption_share


class PolicyAuthor(NucypherTokenActor):
    """Alice base class for blockchain operations, mocking up new policies!"""

    def __init__(self, eth_provider_uri: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.application_agent = ContractAgency.get_agent(
            PREApplicationAgent,
            registry=self.registry,
            eth_provider_uri=eth_provider_uri
        )

    def create_policy(self, *args, **kwargs):
        """Hence the name, a BlockchainPolicyAuthor can create a BlockchainPolicy with themself as the author."""
        from nucypher.policy.policies import Policy

        blockchain_policy = Policy(publisher=self, *args, **kwargs)
        return blockchain_policy


class Investigator(NucypherTokenActor):
    """
    Actor that reports incorrect CFrags to the Adjudicator contract.
    In most cases, Bob will act as investigator, but the actor is generic enough than
    anyone can report CFrags.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.adjudicator_agent = ContractAgency.get_agent(AdjudicatorAgent, registry=self.registry)

    @save_receipt
    def request_evaluation(self, evidence) -> dict:
        receipt = self.adjudicator_agent.evaluate_cfrag(evidence=evidence, transacting_power=self.transacting_power)
        return receipt

    def was_this_evidence_evaluated(self, evidence) -> bool:
        result = self.adjudicator_agent.was_this_evidence_evaluated(evidence=evidence)
        return result
