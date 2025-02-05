<?php

namespace SapientPro\WpMigration\Model\Config;

use Magento\Framework\Data\OptionSourceInterface;
use Magento\Framework\App\ResourceConnection;

class Database implements OptionSourceInterface
{
    private ResourceConnection $resourceConnection;

    public function __construct(ResourceConnection $resourceConnection)
    {
        $this->resourceConnection = $resourceConnection;
    }

    public function toOptionArray(): array
    {
        $connection = $this->resourceConnection->getConnection();

        $databases = $connection->query('SHOW DATABASES');

        $options = [];

        foreach ($databases as $database) {
            $options[] = [
                'value' => $database['Database'],
                'label' => $database['Database']
            ];
        }

        return $options;
    }
}
