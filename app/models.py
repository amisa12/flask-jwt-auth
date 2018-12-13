# app/models.py

import datetime

from app import app, db, bcrypt

import jwt

from sqlalchemy import Column, Integer, DateTime, BigInteger, ForeignKey, Numeric, String, JSON, ARRAY, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# postgresql dialect
# https://docs.sqlalchemy.org/en/latest/dialects/postgresql.html

class BaseModel(Base):
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    date_created = Column(DateTime, default=datetime.datetime.now())
    last_updated = Column(DateTime, default=None)

class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=60),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False

class StatusCodesModel(db.Model,BaseModel):
    __tablename__ = 'status_codes'

    code = Column(String(100), nullable=False)
    description = Column(String(100),nullable=False)


class ModuleModel(db.Model,BaseModel):
    __tablename__ = 'modules'

    module_name = Column(String(35), nullable=False)
    module_cost = Column(String(35),nullable=False)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)
    subscription = Column(String(35), nullable=False)
    queue_name= Column(String(35),nullable=False)


class OrganizationModel(db.Model,BaseModel):
    __tablename__ = 'organization'

    organization_name = Column(String(35), nullable=False)
    created_by = Column(DateTime, nullable=False)
    updated_by = Column(DateTime, nullable=False)
    user_id = Column(BigInteger,ForeignKey('users.id'), index=True)



class UserAppModel(db.Model,BaseModel):
    __tablename__ = 'user_apps'

    app_name = Column(String(35), nullable=False)
    app_description = Column(String(200), nullable=False)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)
    organization_id = Column(BigInteger, ForeignKey('organization.id'), index=True)



class AppModuleModel(db.Model,BaseModel):
    __tablename__ = 'app_modules'

    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)
    module_id = Column(BigInteger, ForeignKey('modules.id'), index=True)
    app_id = Column(BigInteger, ForeignKey('user_apps.id'), index=True)



class AuditTrailModel(db.Model,BaseModel):
    __tablename__ = 'audit_trail'

    actions = Column(String(200), nullable=False)
    user_id = Column(BigInteger, ForeignKey('users.id'), index=True)



class UserKYCModel(db.Model,BaseModel):
    __tablename__ = 'user_kyc'

    full_names = Column(String(35), nullable=False)
    user_id = Column(BigInteger, ForeignKey('users.id'), index=True)
    phone_number = Column(String(35), nullable=False)


class RolesModel(db.Model,BaseModel):
    __tablename__ = 'roles'

    roles = Column(String(35), nullable=False)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class PermissionModel(db.Model,BaseModel):
    __tablename__ = 'permissions'

    permission = Column(String(200), nullable=False)
    role_id = Column(BigInteger,ForeignKey('roles.id'),index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class AppDetailsModel(db.Model,BaseModel):
    __tablename__ = 'app_details'

    consumer_key = Column(String(100), nullable=False)
    consumer_secret = Column(String(100), nullable=False)
    token = Column(String(100), nullable=False)
    token_expiry=Column(DateTime,nullable=False)
    environment= Column(String(100), nullable=False)
    app_id = Column(BigInteger,ForeignKey('users.id'))
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class PaymentTypeModel(db.Model,BaseModel):
    __tablename__ = 'payment_types'

    payment_type_name = Column(String(100), nullable=False)
    payment_type_code = Column(String(100), nullable=False)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class PaymentTypeMappingModel(db.Model,BaseModel):
    __tablename__ = 'payment_type_mapping'

    transaction_volume = Column(String(35), nullable=False)
    payment_type_id = Column(BigInteger,ForeignKey('payment_types.id'), index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)



class PaymentModesModel(db.Model,BaseModel):
    __tablename__ = 'payment_modes'

    payment_mode = Column(String(35), nullable=False)



class PaymentsModel(db.Model,BaseModel):
    __tablename__ = 'payments'

    payment_source = Column(String(200), nullable=False)
    trx_no = Column(String(35), nullable=False)
    amount = Column(Numeric(10,2), nullable=False)
    ext_ref_no = Column(String(35), nullable=False)
    destination = Column(String(200), nullable=False)
    payment_type_mapping_id = Column(BigInteger,ForeignKey('payment_type_mapping.id'), index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class NotificationTemplatesModel(db.Model,BaseModel):
    __tablename__ = 'notification_templates'

    notification_type = Column(String(35), nullable=False)
    notification_code = Column(String(35), nullable=False)
    notification_message = Column(String(35), nullable=False)
    notification_path = Column(String(35), nullable=False)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)


class OrganizationInvoicesModel(db.Model,BaseModel):
    __tablename__ = 'org_invoices'

    from_date = Column(DateTime, nullable=False)
    to_date = Column(DateTime, nullable=False)
    initiator = Column(String(35), nullable=False)
    period = Column(String(35), nullable=False)
    ext_ref_no = Column(String(35), nullable=False)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)


class OrganizationBalanceModel(db.Model,BaseModel):
    __tablename__ = 'organization_balance'

    balance = Column(Numeric(10,2), nullable=False)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)



class OrganizationModuleUsageModel(db.Model,BaseModel):
    __tablename__ = 'organization_module_usage'

    amount_deducted = Column(Numeric(10,2), nullable=False)
    previous_balance = Column(Numeric(10,2), nullable=False)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)



class ModuleChargesModel(db.Model,BaseModel):
    __tablename__ = 'module_charges'

    module_id = Column(BigInteger,ForeignKey('modules.id'))
    organization_id = Column(BigInteger,ForeignKey('organization.id'),index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)



class ModuleChargesRulesModel(db.Model,BaseModel):
    __tablename__ = 'module_charges_rules'

    minimum = Column(Numeric(10,2), nullable=False)
    maximum = Column(Numeric(10,2), nullable=False)
    module_charges_id = Column(BigInteger,ForeignKey('module_charges.id'), index=True)



class ModuleModeRulesModel(db.Model,BaseModel):
    __tablename__ = 'module_mode_rules'

    payment_mode_id =Column(BigInteger,ForeignKey('payment_modes.id'), index=True)
    cycle = Column(String(35), nullable=False)
    module_charges_id = Column(BigInteger,ForeignKey('module_charges.id'), index=True)



class UserPaymentMappingDetailsModel(db.Model,BaseModel):
    __tablename__ = 'user_payment_mapping_detail'

    name = Column(String(35), nullable=False)
    payment_url = Column(String(100), nullable=False)
    callback_url = Column(String(100), nullable=False)
    paybill = Column(String(35), nullable=False)
    payment_type_mapping_id = Column(BigInteger,ForeignKey('payment_type_mapping.id'),index=True)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)


class ChannelModel(db.Model,BaseModel):
    __tablename__ = 'channel'

    name = Column(String(35), nullable=False)
    type = Column(String(100), nullable=False)
    status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)


class ProvidersModel(db.Model,BaseModel):
    __tablename__ = 'providers'
    name= Column(String(35), nullable=False)
    code = Column(String(100), nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class OutboxMessagesModel(db.Model,BaseModel):
    __tablename__ = 'outbox_messages'
    sources=Column(String(200), nullable=False)
    recipients=Column(ARRAY(String), nullable=False)
    organization_id= Column(BigInteger,ForeignKey('organization.id'), index=True)
    type=Column(String(35), nullable=False)
    channel_id= Column(BigInteger,ForeignKey('channel.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class DeliveryReportModel(db.Model,BaseModel):
    __tablename__ = 'delivery_report'
    description= Column(String(35), nullable=False)
    dlr_status =Column(String(100), nullable=False)
    message_id=Column(String(100), nullable=False)
    outbox_message_id=Column(BigInteger,ForeignKey('outbox_messages.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class OrganizationMappingModel(db.Model,BaseModel):
     __tablename__ = 'organization_mapping'
     message_id=Column(BigInteger,ForeignKey('delivery_report.id'), index=True)
     name = Column(String(100), nullable=False)
     status_code_id = Column(BigInteger,ForeignKey('status_codes.id'), index=True)


class TemplatesModel(db.Model,BaseModel):
    __tablename__ = 'templates'
    type= Column(String(35), nullable=False)
    organization_id= Column(BigInteger,ForeignKey('organization.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class ProviderMappingModel(db.Model,BaseModel):
    __tablename__ = 'provider_mapping'
    config=Column (JSON)
    provider_id = Column(BigInteger,ForeignKey('providers.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class MessageTemplatesModel(db.Model,BaseModel):
    __tablename__ = 'message_templates'
    message_id = Column(BigInteger,ForeignKey('delivery_report.id'),index=True)
    message=Column(String(35), nullable=False)
    channel_id= Column(BigInteger,ForeignKey('channel.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class LoanProductModel(db.Model,BaseModel):
    __tablename__ = 'loan_product'
    product_name = Column(String(35),nullable=False)
    type =Column(String(35), nullable=False)
    period_type =Column(String(35), default=None)
    period =Column(Integer, nullable=False)
    fee = Column(Numeric, nullable=False)
    min_amount = Column(Integer, nullable=False)
    max_amount = Column(Integer, nullable=False)
    active_from = Column(DateTime, default=datetime.datetime.now())
    active_to = Column(DateTime, default=None)
    threshold = Column(Numeric, nullable=False)
    has_threshold = Column(Boolean, nullable=False)
    organization_id = Column(BigInteger,ForeignKey('organization.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class OrganizationCustomerModel(db.Model,BaseModel):
    __tablename__ = 'organization_customer'
    id_number = Column(Integer,nullable=False)
    phone_number = Column(Integer,nullable=False)
    full_names = Column(String(50),nullable=False)
    organization_id =Column(BigInteger,ForeignKey('organization.id'),index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)
    score = Column(String(35),nullable=False)
    current_loan_limit =Column(Integer,nullable=False)
    loan_balance = Column(Numeric,nullable=False)
    extras = Column(JSON)



class LoansModel(db.Model,BaseModel):
    __tablename__ = 'loan'
    product_id = Column(BigInteger,ForeignKey('loan_product.id'),index=True)
    external_id =Column(BigInteger,nullable=False)
    principal=Column(Numeric, nullable=False)
    amount_due = Column(Numeric, nullable=False)
    date_due = Column(DateTime,default=None)
    date_disbursed = Column(DateTime, default=None)
    external_status = Column(Integer,nullable=False)
    external_status_desc = Column(String(50),nullable=False)
    customer_id =Column(BigInteger,ForeignKey('organization_customer.id'),index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class PenaltyModel(db.Model,BaseModel):
    __tablename__ = 'penalty'
    product_id = Column(BigInteger,ForeignKey('loan_product.id'),index=True)
    rate=Column(Numeric, nullable=False)
    grace_period = Column(Integer, nullable=False)
    type = Column(String(35),nullable=False)
    period = Column(Integer,nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class LoanPenaltyChargesModel(db.Model,BaseModel):
    __tablename__ = 'loan_penalty_charges'
    loan_id = Column(BigInteger,ForeignKey('loan.id'),index=True)
    amount_charged=Column(Numeric, nullable=False)
    type = Column(String(35),nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class LoanRedemptionModel(db.Model,BaseModel):
    __tablename__ = 'loan_redemption'
    organization_id =Column(BigInteger,ForeignKey('organization.id'),index=True)
    voucher_code=Column(String, nullable=False)
    loan_id =Column(BigInteger,ForeignKey('loan.id'),index=True)
    extras = Column(JSON)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class LoanBalancesModel(db.Model,BaseModel):
    __tablename__ = 'loan_balances'
    loan_id = Column(BigInteger,ForeignKey('loan.id'),index=True)
    current_balance = Column(Integer, nullable=False)
    previous_balance = Column(Integer,nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class LoanProductRulesModel(db.Model,BaseModel):
    __tablename__ = 'loan_product_rules'
    product_id = Column(BigInteger,ForeignKey('loan_product.id'),index=True)
    maximum_loans = Column(Integer, nullable=False)
    maximum_loans_per_user = Column(Integer,nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)


class LoanPaymentsModel(db.Model,BaseModel):
    __tablename__ = 'loan_payment'
    loan_id = Column(BigInteger,ForeignKey('loan.id'),index=True)
    payment_date = Column(DateTime, nullable=False)
    reference = Column(String(50),nullable=False)
    amount_paid = Column(Integer,nullable=False)
    external_id =Column(Integer,nullable=False)
    payment_mode = Column(String(50), nullable=False)
    Source = Column(String(50), nullable=False)
    account_reference =Column(String(50),nullable=False)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)

class LoanRefundsModel(db.Model,BaseModel):
    __tablename__ = 'loan_refunds'
    refund_date = Column(DateTime, nullable=False)
    reference = Column(String(50),nullable=False)
    refund_amount = Column(Integer,nullable=False)
    external_id =Column(Integer,nullable=False)
    payment_id = Column(BigInteger, ForeignKey('loan_payment.id'), index=True)
    status_code_id = Column(BigInteger, ForeignKey('status_codes.id'), index=True)
