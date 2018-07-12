int __init init_cs(void);
void exit_cs(void);

int cs_insert_extent(struct inode *inode, ext4_lblk_t lblk,
              ext4_lblk_t len, ext4_fsblk_t pblk,
              unsigned int status);
void cs_print_tree(struct seq_file *s, struct inode *inode);
struct extent_status find_es_in_tree(struct inode *inode, ext4_fsblk_t lba, unsigned int *offset);
