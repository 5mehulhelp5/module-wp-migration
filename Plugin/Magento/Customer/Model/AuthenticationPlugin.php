<?php

namespace SapientPro\WpMigration\Plugin\Magento\Customer\Model;

use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Model\Authentication;
use Magento\Customer\Model\AccountManagement;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\InvalidEmailOrPasswordException;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\App\ResourceConnection;
use Magento\Store\Model\ScopeInterface;
use Magento\Framework\Math\Random;
use SapientPro\WpMigration\Service\Customer\WpPasswordHash;

class AuthenticationPlugin
{
    /**
     * @var ScopeConfigInterface
     */
    private ScopeConfigInterface $scopeConfig;

    /**
     * @var CustomerRepositoryInterface
     */
    private CustomerRepositoryInterface $customerRepository;

    /**
     * @var ResourceConnection
     */
    private ResourceConnection $resourceConnection;

    /**
     * @var WpPasswordHash
     */
    private WpPasswordHash $wpPasswordHash;

    /**
     * @var AccountManagement
     */
    private AccountManagement $accountManagement;

    /**
     * @var Random
     */
    private Random $mathRandom;

    /**
     * AuthenticationPlugin constructor.
     *
     * @param ScopeConfigInterface $scopeConfig
     * @param CustomerRepositoryInterface $customerRepository
     * @param WpPasswordHash $wpPasswordHash
     * @param AccountManagement $accountManagement
     * @param Random $mathRandom
     * @param ResourceConnection $resourceConnection
     */
    public function __construct(
        ScopeConfigInterface $scopeConfig,
        CustomerRepositoryInterface $customerRepository,
        WpPasswordHash $wpPasswordHash,
        AccountManagement $accountManagement,
        Random $mathRandom,
        ResourceConnection $resourceConnection
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->customerRepository = $customerRepository;
        $this->resourceConnection = $resourceConnection;
        $this->wpPasswordHash = $wpPasswordHash;
        $this->accountManagement = $accountManagement;
        $this->mathRandom = $mathRandom;
    }

    /**
     * After authenticate
     *
     * @param Authentication $authorization
     * @param callable $proceed
     * @param $customerId
     * @param $password
     * @return mixed
     * @throws InvalidEmailOrPasswordException
     */
    public function aroundAuthenticate(Authentication $authorization, callable $proceed, $customerId, $password)
    {
        // Looking for the user in the WordPress database
        $status = $this->scopeConfig->isSetFlag('sp_wp_migration/base/active');

        if (!$status) {
            return $proceed($customerId, $password);
        }

        try {
            $proceed($customerId, $password);
            return true;
        } catch (InvalidEmailOrPasswordException $e) {
            try {
                $customer = $this->customerRepository->getById($customerId);
                $wpDatabaseName = $this->scopeConfig->getValue('sp_wp_migration/base/wp_database', ScopeInterface::SCOPE_STORE);
                $customerEmail = $customer->getEmail();
                $wpUser = $this->resourceConnection->getConnection()->select()
                    ->from($wpDatabaseName . '.wp_users')
                    ->where('user_email = ?', $customerEmail)
                    ->limit(1)
                    ->query();

                $wpUserData = $wpUser->fetch();
                if (!$wpUserData) {
                    throw new NoSuchEntityException();
                }

                $wpHash = $this->wpPasswordHash->hashPassword('!!Test1234!!');
                $result = $this->wpPasswordHash->CheckPassword($password, $wpUserData['user_pass']);
                if ($result) {
                    $newPasswordToken = $this->mathRandom->getUniqueHash();
                    $this->accountManagement->changeResetPasswordLinkToken($customer, $newPasswordToken);
                    $this->accountManagement->resetPassword($customer->getEmail(), $newPasswordToken, $password);
                    return true;
                }
            } catch (NoSuchEntityException $e) {
                throw new InvalidEmailOrPasswordException(__('Invalid login or password.'));
            } catch (LocalizedException $e) {
                throw new InvalidEmailOrPasswordException(__('Undefined error.'));
            } catch (\Zend_Db_Statement_Exception $e) {
                throw new InvalidEmailOrPasswordException(__('Database connection error.'));
            }
        }

        throw new InvalidEmailOrPasswordException(__('Invalid login or password.'));
    }
}
