<?php

namespace Ano\Bundle\SecurityBundle\Security\Acl\Dbal;

use Symfony\Component\Security\Acl\Dbal\MutableAclProvider as BaseProvider;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

class MutableAclProvider extends BaseProvider
{
    public function createOrRetrieveSecurityIdentityId(SecurityIdentityInterface $sid)
    {
        if (false !== $id = $this->connection->executeQuery($this->getSelectSecurityIdentityIdSql($sid))->fetchColumn()) {
            return $id;
        }

        $this->connection->executeQuery($this->getInsertSecurityIdentitySql($sid));

        return $this->connection->executeQuery($this->getSelectSecurityIdentityIdSql($sid))->fetchColumn();
    }
}
