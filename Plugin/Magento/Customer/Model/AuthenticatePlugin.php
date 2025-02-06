<?php

namespace SapientPro\WpMigration\Plugin\Magento\Customer\Model;

use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\AccountManagement;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Customer\Api\Data\CustomerInterfaceFactory;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\Math\Random;
use Magento\Store\Model\ScopeInterface;
use Magento\Store\Model\StoreManagerInterface;
use SapientPro\WpMigration\Service\Customer\WpPasswordHash;

class AuthenticatePlugin
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
     * @var CustomerInterfaceFactory
     */
    private CustomerInterfaceFactory $customerFactory;

    /**
     * @var StoreManagerInterface
     */
    private StoreManagerInterface $storeManager;

    /**
     * AuthenticationPlugin constructor.
     *
     * @param ScopeConfigInterface $scopeConfig
     * @param CustomerRepositoryInterface $customerRepository
     * @param WpPasswordHash $wpPasswordHash
     * @param AccountManagement $accountManagement
     * @param Random $mathRandom
     * @param ResourceConnection $resourceConnection
     * @param CustomerInterfaceFactory $customerFactory
     * @param StoreManagerInterface $storeManager
     */
    public function __construct(
        ScopeConfigInterface $scopeConfig,
        CustomerRepositoryInterface $customerRepository,
        WpPasswordHash $wpPasswordHash,
        AccountManagement $accountManagement,
        Random $mathRandom,
        ResourceConnection $resourceConnection,
        CustomerInterfaceFactory $customerFactory,
        StoreManagerInterface $storeManager
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->customerRepository = $customerRepository;
        $this->resourceConnection = $resourceConnection;
        $this->wpPasswordHash = $wpPasswordHash;
        $this->accountManagement = $accountManagement;
        $this->mathRandom = $mathRandom;
        $this->customerFactory = $customerFactory;
        $this->storeManager = $storeManager;
    }

    /**
     * After authenticate
     *
     * @param AccountManagement $authorization
     * @param $username
     * @param $password
     * @return array
     * @throws LocalizedException
     */
    public function beforeAuthenticate(AccountManagement $authorization, $username, $password): array
    {
        // Looking for the user in the WordPress database
        $status = $this->scopeConfig->isSetFlag('sp_wp_migration/base/active');

        if ($status) {
            try {
                $this->customerRepository->get($username);
            } catch (NoSuchEntityException $exception) {
                $wpDatabaseName = $this->scopeConfig->getValue('sp_wp_migration/base/wp_database', ScopeInterface::SCOPE_STORE);

                $wpUser = $this->resourceConnection->getConnection()->select()
                    ->from($wpDatabaseName . '.wp_users')
                    ->where('user_email = ?', $username)
                    ->limit(1)
                    ->query();

                $wpUserData = $wpUser->fetch();

                if ($wpUserData) {
                    /** @var CustomerInterface $customer */
                    $customer = $this->customerFactory->create();
                    $websiteId  = $this->storeManager->getWebsite()->getWebsiteId();

                    $customer->setWebsiteId($websiteId);
                    $customer->setEmail($username);
                    $customer->setCreatedAt($wpUserData['user_registered']);
                    $customer->setFirstname($wpUserData['display_name']);
                    $customer->setLastname($wpUserData['display_name']);

                    $this->customerRepository->save($customer);
                }
            }
        }

        return [$username, $password];
    }
}
